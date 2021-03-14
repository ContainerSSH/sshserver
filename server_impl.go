package sshserver

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/containerssh/log"
	"github.com/containerssh/service"
	"golang.org/x/crypto/ssh"
)

type server struct {
	cfg                 Config
	logger              log.Logger
	handler             Handler
	listenSocket        net.Listener
	wg                  *sync.WaitGroup
	lock                *sync.Mutex
	clientSockets       map[*ssh.ServerConn]bool
	nextGlobalRequestID uint64
	nextChannelID       uint64
	hostKeys            []ssh.Signer
	shutdownHandlers    *shutdownRegistry
	shuttingDown        bool
}

func (s *server) String() string {
	return "SSH server"
}

func (s *server) RunWithLifecycle(lifecycle service.Lifecycle) error {
	s.lock.Lock()
	alreadyRunning := false
	if s.listenSocket != nil {
		alreadyRunning = true
	} else {
		s.clientSockets = make(map[*ssh.ServerConn]bool)
	}
	s.shuttingDown = false
	s.lock.Unlock()

	if alreadyRunning {
		return log.NewMessage(EAlreadyRunning, "SSH server is already running")
	}

	listenConfig := net.ListenConfig{
		Control: s.socketControl,
	}

	netListener, err := listenConfig.Listen(lifecycle.Context(), "tcp", s.cfg.Listen)
	if err != nil {
		return log.Wrap(err, EStartFailed, "failed to start SSH server on %s", s.cfg.Listen)
	}
	s.listenSocket = netListener
	if err := s.handler.OnReady(); err != nil {
		if err := netListener.Close(); err != nil {
			s.logger.Warning(log.Wrap(err, EListenCloseFailed, "failed to close listen socket after failed startup"))
		}
		return err
	}
	lifecycle.Running()
	s.logger.Info(log.NewMessage(MServiceAvailable, "SSH server running on %s", s.cfg.Listen))

	go func() {
		<-lifecycle.Context().Done()
		if err := s.listenSocket.Close(); err != nil {
			s.logger.Warning(log.Wrap(err, EListenCloseFailed, "failed to close listen socket"))
		}
	}()
	for {
		tcpConn, err := netListener.Accept()
		if err != nil {
			// Assume listen socket closed
			break
		}
		go s.handleConnection(tcpConn)
	}
	lifecycle.Stopping()
	s.shuttingDown = true
	allClientsExited := make(chan struct{})
	shutdownHandlerExited := make(chan struct{}, 1)
	go s.shutdownHandlers.Shutdown(lifecycle.ShutdownContext())
	go s.disconnectClients(lifecycle, allClientsExited)
	go s.shutdownHandler(lifecycle, shutdownHandlerExited)

	s.wg.Wait()
	close(allClientsExited)
	<-shutdownHandlerExited
	return nil
}

func (s *server) disconnectClients(lifecycle service.Lifecycle, allClientsExited chan struct{}) {
	select {
	case <-allClientsExited:
		return
	case <-lifecycle.ShutdownContext().Done():
	}

	s.lock.Lock()
	for serverSocket := range s.clientSockets {
		_ = serverSocket.Close()
	}
	s.clientSockets = map[*ssh.ServerConn]bool{}
	s.lock.Unlock()
}

func (s *server) createPasswordAuthenticator(
	handlerNetworkConnection NetworkConnectionHandler,
	logger log.Logger,
) func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authResponse, err := handlerNetworkConnection.OnAuthPassword(conn.User(), password)
		switch authResponse {
		case AuthResponseSuccess:
			s.logAuthSuccessful(logger, conn, "Password")
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			err = s.wrapAndLogAuthFailure(logger, conn, "Password", err)
			return nil, err
		case AuthResponseUnavailable:
			err = s.wrapAndLogAuthUnavailable(logger, conn, "Password", err)
			return nil, err
		}
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) wrapAndLogAuthUnavailable(
	logger log.Logger,
	conn ssh.ConnMetadata,
	authMethod string,
	err error,
) error {
	err = log.WrapUser(
		err,
		EAuthUnavailable,
		"Authentication is currently unavailable, please try a different authentication method or try again later.",
		"%s authentication for user %s currently unavailable.",
		authMethod,
		conn.User(),
	).
		Label("username", conn.User()).
		Label("method", strings.ToLower(authMethod)).
		Label("reason", err.Error())
	logger.Info(err)
	return err
}

func (s *server) wrapAndLogAuthFailure(logger log.Logger, conn ssh.ConnMetadata, authMethod string, err error) error {
	if err == nil {
		err = log.UserMessage(
			EAuthFailed,
			"Authentication failed.",
			"%s authentication for user %s failed.",
			authMethod,
			conn.User(),
		).
			Label("username", conn.User()).
			Label("method", strings.ToLower(authMethod))
		logger.Info(err)
	} else {
		err = log.WrapUser(
			err,
			EAuthFailed,
			"Authentication failed.",
			"%s authentication for user %s failed.",
			authMethod,
			conn.User(),
		).
			Label("username", conn.User()).
			Label("method", strings.ToLower(authMethod)).
			Label("reason", err.Error())
		logger.Info(err)
	}
	return err
}

func (s *server) logAuthSuccessful(logger log.Logger, conn ssh.ConnMetadata, authMethod string) {
	err := log.UserMessage(
		EAuthSuccessful,
		"Authentication successful.",
		"%s authentication for user %s successful.",
		authMethod,
		conn.User(),
	).Label("username", conn.User()).Label("method", strings.ToLower(authMethod))
	logger.Info(err)
}

func (s *server) createPubKeyAuthenticator(
	handlerNetworkConnection NetworkConnectionHandler,
	logger log.Logger,
) func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
		authResponse, err := handlerNetworkConnection.OnAuthPubKey(conn.User(), authorizedKey)
		switch authResponse {
		case AuthResponseSuccess:
			s.logAuthSuccessful(logger, conn, "Public key")
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			err = s.wrapAndLogAuthFailure(logger, conn, "Public key", err)
			return nil, err
		case AuthResponseUnavailable:
			err = s.wrapAndLogAuthUnavailable(logger, conn, "Public key", err)
			return nil, err
		}
		// This should never happen
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) createKeyboardInteractiveHandler(
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	return func(
		conn ssh.ConnMetadata,
		challenge ssh.KeyboardInteractiveChallenge,
	) (*ssh.Permissions, error) {
		challengeWrapper := func(
			instruction string,
			questions KeyboardInteractiveQuestions,
		) (answers KeyboardInteractiveAnswers, err error) {
			if answers.answers == nil {
				answers.answers = map[string]string{}
			}
			var q []string
			var echos []bool
			for _, question := range questions {
				q = append(q, question.Question)
				echos = append(echos, question.EchoResponse)
			}

			// user, instruction string, questions []string, echos []bool
			answerList, err := challenge(conn.User(), instruction, q, echos)
			for index, rawAnswer := range answerList {
				question := questions[index]
				answers.answers[question.getID()] = rawAnswer
			}
			return answers, err
		}
		authResponse, err := handlerNetworkConnection.OnAuthKeyboardInteractive(conn.User(), challengeWrapper)
		switch authResponse {
		case AuthResponseSuccess:
			s.logAuthSuccessful(logger, conn, "Keyboard-interactive")
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			err = s.wrapAndLogAuthFailure(logger, conn, "Keyboard-interactive", err)
			return nil, err
		case AuthResponseUnavailable:
			err = s.wrapAndLogAuthUnavailable(logger, conn, "Keyboard-interactive", err)
			return nil, err
		}
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) createConfiguration(
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) *ssh.ServerConfig {
	passwordCallback, pubkeyCallback, keyboardInteractiveCallback := s.createAuthenticators(
		handlerNetworkConnection,
		logger,
	)
	serverConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: s.cfg.getKex(),
			Ciphers:      s.cfg.getCiphers(),
			MACs:         s.cfg.getMACs(),
		},
		NoClientAuth:                false,
		MaxAuthTries:                6,
		PasswordCallback:            passwordCallback,
		PublicKeyCallback:           pubkeyCallback,
		KeyboardInteractiveCallback: keyboardInteractiveCallback,
		ServerVersion:               s.cfg.ServerVersion,
		BannerCallback:              func(conn ssh.ConnMetadata) string { return s.cfg.Banner },
	}
	for _, key := range s.hostKeys {
		serverConfig.AddHostKey(key)
	}
	return serverConfig
}

func (s *server) createAuthenticators(
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) (
	func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error),
	func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error),
	func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error),
) {
	passwordCallback := s.createPasswordCallback(handlerNetworkConnection, logger)
	pubkeyCallback := s.createPubKeyCallback(handlerNetworkConnection, logger)
	keyboardInteractiveCallback := s.createKeyboardInteractiveCallback(handlerNetworkConnection, logger)
	return passwordCallback, pubkeyCallback, keyboardInteractiveCallback
}

func (s *server) createKeyboardInteractiveCallback(
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) func(conn ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	keyboardInteractiveHandler := s.createKeyboardInteractiveHandler(handlerNetworkConnection, logger)
	keyboardInteractiveCallback := func(
		conn ssh.ConnMetadata,
		challenge ssh.KeyboardInteractiveChallenge,
	) (*ssh.Permissions, error) {
		permissions, err := keyboardInteractiveHandler(conn, challenge)
		if err != nil {
			return permissions, err
		}
		// HACK: check HACKS.md "OnHandshakeSuccess handler"
		sshConnectionHandler, err := handlerNetworkConnection.OnHandshakeSuccess(conn.User())
		if err != nil {
			err = log.WrapUser(
				err,
				EBackendRejected,
				"Authentication currently unavailable, please try again later.",
				"The backend has rejected the user after successful authentication.",
			)
			logger.Error(err)
			return permissions, err
		}
		handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
		return permissions, err
	}
	return keyboardInteractiveCallback
}

func (s *server) createPubKeyCallback(
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	pubKeyHandler := s.createPubKeyAuthenticator(handlerNetworkConnection, logger)
	pubkeyCallback := func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		permissions, err := pubKeyHandler(conn, key)
		if err != nil {
			return permissions, err
		}
		// HACK: check HACKS.md "OnHandshakeSuccess handler"
		sshConnectionHandler, err := handlerNetworkConnection.OnHandshakeSuccess(conn.User())
		if err != nil {
			err = log.WrapUser(
				err,
				EBackendRejected,
				"Authentication currently unavailable, please try again later.",
				"The backend has rejected the user after successful authentication.",
			)
			logger.Error(err)
			return permissions, err
		}
		handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
		return permissions, err
	}
	return pubkeyCallback
}

func (s *server) createPasswordCallback(
	handlerNetworkConnection *networkConnectionWrapper,
	logger log.Logger,
) func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	passwordHandler := s.createPasswordAuthenticator(handlerNetworkConnection, logger)
	passwordCallback := func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		permissions, err := passwordHandler(conn, password)
		if err != nil {
			return permissions, err
		}
		// HACK: check HACKS.md "OnHandshakeSuccess handler"
		sshConnectionHandler, err := handlerNetworkConnection.OnHandshakeSuccess(conn.User())
		if err != nil {
			err = log.WrapUser(
				err,
				EBackendRejected,
				"Authentication currently unavailable, please try again later.",
				"The backend has rejected the user after successful authentication.",
			)
			logger.Error(err)
			return permissions, err
		}
		handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
		return permissions, err
	}
	return passwordCallback
}

// HACK: check HACKS.md "OnHandshakeSuccess handler"
type networkConnectionWrapper struct {
	NetworkConnectionHandler
	sshConnectionHandler SSHConnectionHandler
}

func (n *networkConnectionWrapper) OnShutdown(shutdownContext context.Context) {
	n.sshConnectionHandler.OnShutdown(shutdownContext)
}

func (s *server) handleConnection(conn net.Conn) {
	addr := conn.RemoteAddr().(*net.TCPAddr)
	connectionID := GenerateConnectionID()
	logger := s.logger.
		WithLabel("remoteAddr", addr.IP.String()).
		WithLabel("connectionId", connectionID)
	handlerNetworkConnection, err := s.handler.OnNetworkConnection(*addr, connectionID)
	if err != nil {
		logger.Info(err)
		_ = conn.Close()
		return
	}
	shutdownHandlerID := fmt.Sprintf("network-%s", connectionID)
	s.shutdownHandlers.Register(shutdownHandlerID, handlerNetworkConnection)

	logger.Debug(log.NewMessage(
		MConnected, "Client connected",
	))

	// HACK: check HACKS.md "OnHandshakeSuccess handler"
	wrapper := networkConnectionWrapper{
		NetworkConnectionHandler: handlerNetworkConnection,
	}

	sshConn, channels, globalRequests, err := ssh.NewServerConn(conn, s.createConfiguration(&wrapper, logger))
	if err != nil {
		logger.Info(log.Wrap(err, EHandshakeFailed, "SSH handshake failed"))
		handlerNetworkConnection.OnHandshakeFailed(err)
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		logger.Debug(log.NewMessage(MDisconnected, "Client disconnected"))
		handlerNetworkConnection.OnDisconnect()
		_ = conn.Close()
		return
	}
	logger = logger.WithLabel("username", sshConn.User())
	logger.Debug(log.NewMessage(MHandshakeSuccessful, "SSH handshake successful"))
	s.lock.Lock()
	s.clientSockets[sshConn] = true
	sshShutdownHandlerID := fmt.Sprintf("ssh-%s", connectionID)
	s.lock.Unlock()

	s.wg.Add(1)
	go func() {
		_ = sshConn.Wait()
		logger.Debug(log.NewMessage(MDisconnected, "Client disconnected"))
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		s.shutdownHandlers.Unregister(sshShutdownHandlerID)
		handlerNetworkConnection.OnDisconnect()
		s.wg.Done()
	}()
	// HACK: check HACKS.md "OnHandshakeSuccess handler"
	handlerSSHConnection := wrapper.sshConnectionHandler
	s.shutdownHandlers.Register(sshShutdownHandlerID, handlerSSHConnection)

	go s.handleChannels(connectionID, channels, handlerSSHConnection, logger)
	go s.handleGlobalRequests(globalRequests, handlerSSHConnection, logger)
}

func (s *server) handleGlobalRequests(
	requests <-chan *ssh.Request,
	connection SSHConnectionHandler,
	logger log.Logger,
) {
	for {
		request, ok := <-requests
		if !ok {
			break
		}
		requestID := s.nextGlobalRequestID
		s.nextGlobalRequestID++
		logger.Debug(log.NewMessage(EUnsupportedGlobalRequest, "Unsupported global request").Label("type", request.Type))
		connection.OnUnsupportedGlobalRequest(requestID, request.Type, request.Payload)
		if request.WantReply {
			if err := request.Reply(false, []byte("request type not supported")); err != nil {
				logger.Debug(log.Wrap(err, EReplyFailed, "failed to send reply to global request type %s", request.Type))
			}
		}
	}
}

func (s *server) handleChannels(
	connectionID string,
	channels <-chan ssh.NewChannel,
	connection SSHConnectionHandler,
	logger log.Logger,
) {
	for {
		newChannel, ok := <-channels
		if !ok {
			break
		}
		channelID := s.nextChannelID
		s.nextChannelID++
		logger = logger.WithLabel("channelId", channelID)
		if newChannel.ChannelType() != "session" {
			logger.Debug(log.NewMessage(EUnsupportedChannelType, "Unsupported channel type requested").Label("type", newChannel.ChannelType()))
			connection.OnUnsupportedChannel(channelID, newChannel.ChannelType(), newChannel.ExtraData())
			if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
				logger.Debug("failed to send channel rejection for channel type %s", newChannel.ChannelType())
			}
			continue
		}
		go s.handleSessionChannel(connectionID, channelID, newChannel, connection, logger)
	}
}

type envRequestPayload struct {
	Name  string
	Value string
}

type execRequestPayload struct {
	Exec string
}

type ptyRequestPayload struct {
	Term     string
	Columns  uint32
	Rows     uint32
	Width    uint32
	Height   uint32
	ModeList []byte
}

type shellRequestPayload struct {
}

type signalRequestPayload struct {
	Signal string
}

type subsystemRequestPayload struct {
	Subsystem string
}

type windowRequestPayload struct {
	Columns uint32
	Rows    uint32
	Width   uint32
	Height  uint32
}

type exitStatusPayload struct {
	ExitStatus uint32
}

type exitSignalPayload struct {
	Signal       string
	CoreDumped   bool
	ErrorMessage string
	LanguageTag  string
}

type requestType string

const (
	requestTypeEnv       requestType = "env"
	requestTypePty       requestType = "pty-req"
	requestTypeShell     requestType = "shell"
	requestTypeExec      requestType = "exec"
	requestTypeSubsystem requestType = "subsystem"
	requestTypeWindow    requestType = "window-change"
	requestTypeSignal    requestType = "signal"
)

type channelWrapper struct {
	channel        ssh.Channel
	logger         log.Logger
	lock           *sync.Mutex
	exitSent       bool
	exitSignalSent bool
	closedWrite    bool
	closed         bool
}

func (c *channelWrapper) Stdin() io.Reader {
	if c.channel == nil {
		panic(fmt.Errorf("BUG: stdin requested before channel is open"))
	}
	return c.channel
}

func (c *channelWrapper) Stdout() io.Writer {
	if c.channel == nil {
		panic(fmt.Errorf("BUG: stdout requested before channel is open"))
	}
	return c.channel
}

func (c *channelWrapper) Stderr() io.Writer {
	if c.channel == nil {
		panic(fmt.Errorf("BUG: stderr requested before channel is open"))
	}
	return c.channel.Stderr()
}

func (c *channelWrapper) ExitStatus(exitCode uint32) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: exit status sent before channel is open"))
	}
	c.logger.Debug(log.NewMessage(
		MExit,
		"Program exited with status %d",
		exitCode,
	).Label("exitCode", exitCode))
	if c.exitSent || c.closed {
		return
	}
	c.exitSent = true
	if _, err := c.channel.SendRequest(
		"exit-status",
		false,
		ssh.Marshal(exitStatusPayload{
			ExitStatus: exitCode,
		})); err != nil {
		if !errors.Is(err, io.EOF) {
			c.logger.Debug(log.Wrap(
				err,
				EExitCodeFailed,
				"Failed to send exit status to client",
			))
		}
	}
}

func (c *channelWrapper) ExitSignal(signal string, coreDumped bool, errorMessage string, languageTag string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: exit signal sent before channel is open"))
	}
	c.logger.Debug(log.NewMessage(
		MExitSignal,
		"Program exited with signal %s",
		signal,
	).Label("signal", signal).Label("coreDumped", coreDumped))
	if c.exitSignalSent || c.closed {
		return
	}
	c.exitSignalSent = true
	if _, err := c.channel.SendRequest(
		"exit-signal",
		false,
		ssh.Marshal(exitSignalPayload{
			Signal:       signal,
			CoreDumped:   coreDumped,
			ErrorMessage: errorMessage,
			LanguageTag:  languageTag,
		})); err != nil {
		if !errors.Is(err, io.EOF) {
			c.logger.Debug(log.Wrap(
				err,
				EExitCodeFailed,
				"Failed to send exit status to client",
			))
		}
	}
}

func (c *channelWrapper) CloseWrite() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: channel closed for writing before channel is open"))
	}
	if c.closed || c.closedWrite {
		return nil
	}
	return c.channel.CloseWrite()
}

func (c *channelWrapper) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: channel closed before channel is open"))
	}
	c.closed = true
	return c.channel.Close()
}

func (c *channelWrapper) onClose() {
	c.closed = true
}

func (s *server) handleSessionChannel(
	connectionID string,
	channelID uint64,
	newChannel ssh.NewChannel,
	connection SSHConnectionHandler,
	logger log.Logger,
) {
	channelCallbacks := &channelWrapper{
		logger: logger,
		lock:   &sync.Mutex{},
	}
	handlerChannel, rejection := connection.OnSessionChannel(channelID, newChannel.ExtraData(), channelCallbacks)
	if rejection != nil {
		logger.Debug(log.Wrap(rejection, MNewChannelRejected, "New SSH channel rejected").Label("type", newChannel.ChannelType()))

		if err := newChannel.Reject(rejection.Reason(), rejection.Message()); err != nil {
			logger.Debug(log.Wrap(rejection, EReplyFailed, "Failed to send reply to channel request"))
		}
		return
	}
	shutdownHandlerID := fmt.Sprintf("session-%s-%d", connectionID, channelID)
	s.shutdownHandlers.Register(shutdownHandlerID, handlerChannel)
	channel, requests, err := newChannel.Accept()
	if err != nil {
		logger.Debug(log.Wrap(err, EReplyFailed, "failed to accept session channel"))
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		return
	}
	logger.Debug(log.NewMessage(MNewChannel, "New SSH channel").Label("type", newChannel.ChannelType()))
	channelCallbacks.channel = channel
	nextRequestID := uint64(0)
	for {
		request, ok := <-requests
		if !ok {
			s.shutdownHandlers.Unregister(shutdownHandlerID)
			channelCallbacks.onClose()
			handlerChannel.OnClose()
			break
		}
		requestID := nextRequestID
		nextRequestID++
		s.handleChannelRequest(requestID, request, handlerChannel, logger)
	}
}

func (s *server) unmarshalEnv(request *ssh.Request) (payload envRequestPayload, err error) {
	return payload, ssh.Unmarshal(request.Payload, &payload)
}

func (s *server) unmarshalPty(request *ssh.Request) (payload ptyRequestPayload, err error) {
	return payload, ssh.Unmarshal(request.Payload, &payload)
}

func (s *server) unmarshalShell(request *ssh.Request) (payload shellRequestPayload, err error) {
	if len(request.Payload) != 0 {
		err = ssh.Unmarshal(request.Payload, &payload)
	}
	return payload, err
}

func (s *server) unmarshalExec(request *ssh.Request) (payload execRequestPayload, err error) {
	return payload, ssh.Unmarshal(request.Payload, &payload)
}

func (s *server) unmarshalSubsystem(request *ssh.Request) (payload subsystemRequestPayload, err error) {
	return payload, ssh.Unmarshal(request.Payload, &payload)
}

func (s *server) unmarshalWindow(request *ssh.Request) (payload windowRequestPayload, err error) {
	return payload, ssh.Unmarshal(request.Payload, &payload)
}

func (s *server) unmarshalSignal(request *ssh.Request) (payload signalRequestPayload, err error) {
	return payload, ssh.Unmarshal(request.Payload, &payload)
}

func (s *server) unmarshalPayload(request *ssh.Request) (payload interface{}, err error) {
	switch requestType(request.Type) {
	case requestTypeEnv:
		return s.unmarshalEnv(request)
	case requestTypePty:
		return s.unmarshalPty(request)
	case requestTypeShell:
		return s.unmarshalShell(request)
	case requestTypeExec:
		return s.unmarshalExec(request)
	case requestTypeSubsystem:
		return s.unmarshalSubsystem(request)
	case requestTypeWindow:
		return s.unmarshalWindow(request)
	case requestTypeSignal:
		return s.unmarshalSignal(request)
	default:
		return nil, nil
	}
}

func (s *server) handleChannelRequest(
	requestID uint64,
	request *ssh.Request,
	sessionChannel SessionChannelHandler,
	logger log.Logger,
) {
	reply := func(success bool, message string, reason error) {
		if request.WantReply {
			if err := request.Reply(
				success,
				[]byte(message),
			); err != nil {
				logger.Debug(log.Wrap(
					err,
					EReplyFailed,
					"Failed to send reply to client",
				))
			}
		}
	}
	payload, err := s.unmarshalPayload(request)
	if payload == nil {
		sessionChannel.OnUnsupportedChannelRequest(requestID, request.Type, request.Payload)
		reply(false, fmt.Sprintf("unsupported request type: %s", request.Type), nil)
		return
	}
	if err != nil {
		logger.Debug(log.Wrap(
			err,
			EDecodeFailed,
			"failed to unmarshal %s request payload",
			request.Type,
		))
		sessionChannel.OnFailedDecodeChannelRequest(requestID, request.Type, request.Payload, err)
		reply(false, "failed to unmarshal payload", nil)
		return
	}
	logger.Debug(log.NewMessage(
		MChannelRequest,
		"%s channel request from client",
		request.Type,
	).Label("requestType", request.Type))
	if err := s.handleDecodedChannelRequest(
		requestID,
		requestType(request.Type),
		payload,
		sessionChannel,
	); err != nil {
		logger.Debug(log.NewMessage(
			MChannelRequestFailed,
			"%s channel request from client failed",
			request.Type,
		).Label("requestType", request.Type))
		reply(false, err.Error(), err)
		return
	}
	logger.Debug(log.NewMessage(
		MChannelRequestSuccessful,
		"%s channel request from client successful",
		request.Type,
	).Label("requestType", request.Type))
	reply(true, "", nil)
}

func (s *server) handleDecodedChannelRequest(
	requestID uint64,
	requestType requestType,
	payload interface{},
	sessionChannel SessionChannelHandler,
) error {
	switch requestType {
	case requestTypeEnv:
		return s.onEnvRequest(requestID, sessionChannel, payload)
	case requestTypePty:
		return s.onPtyRequest(requestID, sessionChannel, payload)
	case requestTypeShell:
		return s.onShell(requestID, sessionChannel)
	case requestTypeExec:
		return s.onExec(requestID, sessionChannel, payload)
	case requestTypeSubsystem:
		return s.onSubsystem(requestID, sessionChannel, payload)
	case requestTypeWindow:
		return s.onChannel(requestID, sessionChannel, payload)
	case requestTypeSignal:
		return s.onSignal(requestID, sessionChannel, payload)
	}
	return nil
}

func (s *server) onEnvRequest(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnEnvRequest(
		requestID,
		payload.(envRequestPayload).Name,
		payload.(envRequestPayload).Value,
	)
}

func (s *server) onPtyRequest(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnPtyRequest(
		requestID,
		payload.(ptyRequestPayload).Term,
		payload.(ptyRequestPayload).Columns,
		payload.(ptyRequestPayload).Rows,
		payload.(ptyRequestPayload).Width,
		payload.(ptyRequestPayload).Height,
		payload.(ptyRequestPayload).ModeList,
	)
}

func (s *server) onShell(
	requestID uint64,
	sessionChannel SessionChannelHandler,
) error {
	return sessionChannel.OnShell(
		requestID,
	)
}

func (s *server) onExec(
	requestID uint64,
	sessionChannel SessionChannelHandler,
	payload interface{},
) error {
	return sessionChannel.OnExecRequest(
		requestID,
		payload.(execRequestPayload).Exec,
	)
}

func (s *server) onSignal(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnSignal(
		requestID,
		payload.(signalRequestPayload).Signal,
	)
}

func (s *server) onSubsystem(
	requestID uint64,
	sessionChannel SessionChannelHandler,
	payload interface{},
) error {
	return sessionChannel.OnSubsystem(
		requestID,
		payload.(subsystemRequestPayload).Subsystem,
	)
}

func (s *server) onChannel(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnWindow(
		requestID,
		payload.(windowRequestPayload).Columns,
		payload.(windowRequestPayload).Rows,
		payload.(windowRequestPayload).Width,
		payload.(windowRequestPayload).Height,
	)
}

func (s *server) shutdownHandler(lifecycle service.Lifecycle, exited chan struct{}) {
	s.handler.OnShutdown(lifecycle.ShutdownContext())
	exited <- struct{}{}
}

type shutdownHandler interface {
	OnShutdown(shutdownContext context.Context)
}

type shutdownRegistry struct {
	lock      *sync.Mutex
	callbacks map[string]shutdownHandler
}

func (s *shutdownRegistry) Register(key string, handler shutdownHandler) {
	s.lock.Lock()
	s.callbacks[key] = handler
	s.lock.Unlock()
}

func (s *shutdownRegistry) Unregister(key string) {
	s.lock.Lock()
	delete(s.callbacks, key)
	s.lock.Unlock()
}

func (s *shutdownRegistry) Shutdown(shutdownContext context.Context) {
	wg := &sync.WaitGroup{}
	s.lock.Lock()
	wg.Add(len(s.callbacks))
	for _, handler := range s.callbacks {
		h := handler
		go func() {
			defer wg.Done()
			h.OnShutdown(shutdownContext)
		}()
	}
	s.lock.Unlock()
	wg.Wait()
}
