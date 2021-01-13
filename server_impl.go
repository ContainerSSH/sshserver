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
		return fmt.Errorf("SSH server is already running")
	}

	listenConfig := net.ListenConfig{
		Control: s.socketControl,
	}

	netListener, err := listenConfig.Listen(lifecycle.Context(), "tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("failed to start SSH server on %s (%w)", s.cfg.Listen, err)
	}
	s.listenSocket = netListener
	if err := s.handler.OnReady(); err != nil {
		if err := netListener.Close(); err != nil {
			s.logger.Warningf("failed to close listen socket after failed startup (%v)", err)
		}
		return err
	}
	lifecycle.Running()
	s.logger.Debugf("SSH server running on %s", s.cfg.Listen)

	go func() {
		<-lifecycle.Context().Done()
		if err := s.listenSocket.Close(); err != nil {
			s.logger.Errorf("failed to close listen socket (%v)", err)
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
) func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authResponse, err := handlerNetworkConnection.OnAuthPassword(conn.User(), password)
		switch authResponse {
		case AuthResponseSuccess:
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			return nil, fmt.Errorf("authentication failed")
		case AuthResponseUnavailable:
			s.logger.Warningf("authentication backend currently unavailable (%v)", err)
			return nil, fmt.Errorf("authentication currently unavailable")
		}
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) createPubKeyAuthenticator(
	handlerNetworkConnection NetworkConnectionHandler,
) func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
		authResponse, err := handlerNetworkConnection.OnAuthPubKey(conn.User(), authorizedKey)
		switch authResponse {
		case AuthResponseSuccess:
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			return nil, fmt.Errorf("authentication failed")
		case AuthResponseUnavailable:
			s.logger.Warningf("authentication backend currently unavailable (%v)", err)
			return nil, fmt.Errorf("authentication currently unavailable")
		}
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) createKeyboardInteractiveHandler(handlerNetworkConnection *networkConnectionWrapper) func(
	conn ssh.ConnMetadata,
	challenge ssh.KeyboardInteractiveChallenge,
) (*ssh.Permissions, error) {
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
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			return nil, fmt.Errorf("authentication failed")
		case AuthResponseUnavailable:
			s.logger.Warningf("authentication backend currently unavailable (%v)", err)
			return nil, fmt.Errorf("authentication currently unavailable")
		}
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) createConfiguration(handlerNetworkConnection *networkConnectionWrapper) *ssh.ServerConfig {
	passwordHandler := s.createPasswordAuthenticator(handlerNetworkConnection)
	pubKeyHandler := s.createPubKeyAuthenticator(handlerNetworkConnection)
	keyboardInteractiveHandler := s.createKeyboardInteractiveHandler(handlerNetworkConnection)
	serverConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: s.cfg.getKex(),
			Ciphers:      s.cfg.getCiphers(),
			MACs:         s.cfg.getMACs(),
		},
		NoClientAuth: false,
		MaxAuthTries: 6,
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			permissions, err := passwordHandler(conn, password)
			if err != nil {
				return permissions, err
			}
			// HACK: check HACKS.md "OnHandshakeSuccess handler"
			sshConnectionHandler, err := handlerNetworkConnection.OnHandshakeSuccess(conn.User())
			if err != nil {
				return permissions, err
			}
			handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
			return permissions, err
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			permissions, err := pubKeyHandler(conn, key)
			if err != nil {
				return permissions, err
			}
			// HACK: check HACKS.md "OnHandshakeSuccess handler"
			sshConnectionHandler, err := handlerNetworkConnection.OnHandshakeSuccess(conn.User())
			if err != nil {
				return permissions, err
			}
			handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
			return permissions, err
		},
		KeyboardInteractiveCallback: func(
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
				return permissions, err
			}
			handlerNetworkConnection.sshConnectionHandler = sshConnectionHandler
			return permissions, err
		},
		ServerVersion:  s.cfg.ServerVersion,
		BannerCallback: func(conn ssh.ConnMetadata) string { return s.cfg.Banner },
	}
	for _, key := range s.hostKeys {
		serverConfig.AddHostKey(key)
	}
	return serverConfig
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
	handlerNetworkConnection, err := s.handler.OnNetworkConnection(*addr, connectionID)
	if err != nil {
		s.logger.Infoe(err)
		_ = conn.Close()
		return
	}
	shutdownHandlerID := fmt.Sprintf("network-%s", connectionID)
	s.shutdownHandlers.Register(shutdownHandlerID, handlerNetworkConnection)
	s.logger.Debugf("Client connected: %s", addr.IP.String())

	// HACK: check HACKS.md "OnHandshakeSuccess handler"
	wrapper := networkConnectionWrapper{
		NetworkConnectionHandler: handlerNetworkConnection,
	}

	sshConn, channels, globalRequests, err := ssh.NewServerConn(conn, s.createConfiguration(&wrapper))
	if err != nil {
		s.logger.Debugf("SSH handshake failed for %s (%v)", addr.IP.String(), err)
		handlerNetworkConnection.OnHandshakeFailed(err)
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		handlerNetworkConnection.OnDisconnect()
		_ = conn.Close()
		return
	}
	s.lock.Lock()
	s.clientSockets[sshConn] = true
	sshShutdownHandlerID := fmt.Sprintf("ssh-%s", connectionID)
	s.lock.Unlock()

	s.wg.Add(1)
	go func() {
		_ = sshConn.Wait()
		s.logger.Debugf("Client disconnected: %s", addr.IP.String())
		s.shutdownHandlers.Unregister(shutdownHandlerID)
		s.shutdownHandlers.Unregister(sshShutdownHandlerID)
		handlerNetworkConnection.OnDisconnect()
		s.wg.Done()
	}()
	// HACK: check HACKS.md "OnHandshakeSuccess handler"
	handlerSSHConnection := wrapper.sshConnectionHandler
	s.shutdownHandlers.Register(sshShutdownHandlerID, handlerSSHConnection)

	go s.handleChannels(connectionID, channels, handlerSSHConnection)
	go s.handleGlobalRequests(globalRequests, handlerSSHConnection)
}

func (s *server) handleGlobalRequests(requests <-chan *ssh.Request, connection SSHConnectionHandler) {
	for {
		request, ok := <-requests
		if !ok {
			break
		}
		requestID := s.nextGlobalRequestID
		s.nextGlobalRequestID++
		connection.OnUnsupportedGlobalRequest(requestID, request.Type, request.Payload)
		if request.WantReply {
			if err := request.Reply(false, []byte("request type not supported")); err != nil {
				s.logger.Debugf("failed to send reply to global request type %s (%v)", request.Type, err)
			}
		}
	}
}

func (s *server) handleChannels(connectionID string, channels <-chan ssh.NewChannel, connection SSHConnectionHandler) {
	for {
		newChannel, ok := <-channels
		if !ok {
			break
		}
		channelID := s.nextChannelID
		s.nextChannelID++
		if newChannel.ChannelType() != "session" {
			connection.OnUnsupportedChannel(channelID, newChannel.ChannelType(), newChannel.ExtraData())
			if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
				s.logger.Debugf("failed to send channel rejection for channel type %s", newChannel.ChannelType())
			}
			continue
		}
		go s.handleSessionChannel(connectionID, channelID, newChannel, connection)
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
			c.logger.Debugf("failed to send exit status to client (%v)", err)
		}
	}
}

func (c *channelWrapper) ExitSignal(signal string, coreDumped bool, errorMessage string, languageTag string) {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.channel == nil {
		panic(fmt.Errorf("BUG: exit signal sent before channel is open"))
	}
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
			c.logger.Debugf("failed to send exit status to client (%v)", err)
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

func (s *server) handleSessionChannel(connectionID string, channelID uint64, newChannel ssh.NewChannel, connection SSHConnectionHandler) {
	channelCallbacks := &channelWrapper{
		logger: s.logger,
		lock:   &sync.Mutex{},
	}
	handlerChannel, rejection := connection.OnSessionChannel(channelID, newChannel.ExtraData(), channelCallbacks)
	if rejection != nil {
		if err := newChannel.Reject(rejection.Reason(), rejection.Message()); err != nil {
			s.logger.Debugf("failed to send session channel rejection", err)
		}
		return
	}
	shutdownHandlerID := fmt.Sprintf("session-%s-%d", connectionID, channelID)
	s.shutdownHandlers.Register(shutdownHandlerID, handlerChannel)
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.logger.Debugf("failed to accept session channel (%v)", err)
		return
	}
	channelCallbacks.channel = channel
	nextRequestID := uint64(0)
	for {
		request, ok := <-requests
		if !ok {
			channelCallbacks.onClose()
			handlerChannel.OnClose()
			break
		}
		requestID := nextRequestID
		nextRequestID++
		s.handleChannelRequest(requestID, request, handlerChannel)
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
) {
	reply := func(success bool, message string, reason error) {
		if request.WantReply {
			if err := request.Reply(
				success,
				[]byte(message),
			); err != nil {
				s.logger.Debugf("failed to send reply (%v)", err)
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
		s.logger.Debugf("failed to unmarshal %s request payload %v (%v)", request.Type, request.Payload, err)
		sessionChannel.OnFailedDecodeChannelRequest(requestID, request.Type, request.Payload, err)
		reply(false, "failed to unmarshal payload", nil)
		return
	}
	if err := s.handleDecodedChannelRequest(
		requestID,
		requestType(request.Type),
		payload,
		sessionChannel,
	); err != nil {
		reply(false, err.Error(), err)
		return
	}
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
