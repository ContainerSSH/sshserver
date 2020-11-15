package sshserver

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/containerssh/log"
	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

type server struct {
	cfg                 Config
	logger              log.Logger
	ctx                 context.Context
	shutdownContext     context.Context
	cancelFunc          context.CancelFunc
	handler             Handler
	listenSocket        net.Listener
	wg                  *sync.WaitGroup
	lock                *sync.Mutex
	clientSockets       map[*ssh.ServerConn]bool
	nextGlobalRequestID uint64
	nextChannelID       uint64
}

func (s *server) Shutdown(shutdownContext context.Context) {
	s.lock.Lock()
	if s.listenSocket == nil {
		return
	}
	s.handler.OnShutdown(shutdownContext)
	if s.listenSocket != nil {
		if err := s.listenSocket.Close(); err != nil {
			s.logger.Errorf("failed to close listen socket (%v)", err)
		}
		s.listenSocket = nil
	}
	s.cancelFunc()
	s.shutdownContext = shutdownContext
	s.lock.Unlock()

	done := make(chan bool)
	go func() {
		if shutdownContext.Done() == nil {
			<-done
			return
		}
		select {
		case <-shutdownContext.Done():
			//The shutdown context has expired and the server hasn't shut down, close existing connections.
			s.lock.Lock()
			for serverSocket := range s.clientSockets {
				if err := serverSocket.Close(); err != nil {
					s.logger.Debugf(
						"failed to close client socket for %s (%v)",
						serverSocket.RemoteAddr().String(),
						err,
					)
				}
			}
			s.clientSockets = map[*ssh.ServerConn]bool{}
			s.lock.Unlock()
		case <-done:
		}
	}()
	s.wg.Wait()
	done <- true
}

func (s *server) Run() error {
	s.lock.Lock()
	alreadyRunning := false
	if s.listenSocket != nil {
		alreadyRunning = true
	} else {
		s.clientSockets = make(map[*ssh.ServerConn]bool)
		// Reset shutdown context in case of a second run
		s.shutdownContext = nil
	}
	s.lock.Unlock()

	if alreadyRunning {
		return fmt.Errorf("SSH server is already running")
	}

	s.logger.Debugf("starting SSH server on %s", s.cfg.Listen)
	netListener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("failed to start SSH server on %s (%w)", s.cfg.Listen, err)
	}
	s.listenSocket = netListener
	if err := s.handler.OnReady(); err != nil {
		return err
	}
	s.logger.Debugf("SSH server running on %s", s.cfg.Listen)

	for {
		tcpConn, err := netListener.Accept()
		if err != nil {
			// Assume listen socket closed
			break
		}
		go s.handleConnection(tcpConn)
		select {
		case <-s.ctx.Done():
			break
		default:
		}
	}
	// Wait for all connections to finish
	s.wg.Wait()
	return nil
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
		authResponse, err := handlerNetworkConnection.OnAuthPubKey(conn.User(), pubKey.Marshal())
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

func (s *server) createConfiguration(handlerNetworkConnection NetworkConnectionHandler) *ssh.ServerConfig {
	serverConfig := &ssh.ServerConfig{
		Config: ssh.Config{
			KeyExchanges: s.cfg.getKex(),
			Ciphers:      s.cfg.getCiphers(),
			MACs:         s.cfg.getMACs(),
		},
		NoClientAuth:      false,
		MaxAuthTries:      6,
		PasswordCallback:  s.createPasswordAuthenticator(handlerNetworkConnection),
		PublicKeyCallback: s.createPubKeyAuthenticator(handlerNetworkConnection),
		ServerVersion:     s.cfg.ServerVersion,
		BannerCallback:    func(conn ssh.ConnMetadata) string { return s.cfg.Banner },
	}
	for _, key := range s.cfg.HostKeys {
		serverConfig.AddHostKey(key)
	}
	return serverConfig
}

func (s *server) handleConnection(conn net.Conn) {
	addr := conn.RemoteAddr().(*net.TCPAddr)
	connectionID, err := uuid.New().MarshalBinary()
	if err != nil {
		s.logger.Warningf("failed to generate unique connection ID for %s (%w)", addr.IP.String(), err)
		_ = conn.Close()
		return
	}
	handlerNetworkConnection, err := s.handler.OnNetworkConnection(*addr, connectionID)
	if err != nil {
		s.logger.Infoe(err)
		_ = conn.Close()
		return
	}
	s.logger.Debugf("client connected: %s", addr.IP.String())

	sshConn, channels, globalRequests, err := ssh.NewServerConn(conn, s.createConfiguration(handlerNetworkConnection))
	if err != nil {
		s.logger.Debugf("SSH handshake failed for %s (%v)", addr.IP.String(), err)
		handlerNetworkConnection.OnHandshakeFailed(err)
		handlerNetworkConnection.OnDisconnect()
		_ = conn.Close()
		return
	}
	s.lock.Lock()
	s.clientSockets[sshConn] = true
	s.lock.Unlock()
	s.wg.Add(1)
	go func() {
		_ = sshConn.Wait()
		s.logger.Debugf("client disconnected: %s", addr.IP.String())
		handlerNetworkConnection.OnDisconnect()
		s.wg.Done()
	}()
	handlerSSHConnection, failureReason := handlerNetworkConnection.OnHandshakeSuccess()
	if failureReason != nil {
		s.logger.Debugf("handshake success handler returned with error (%v)", err)
		// No need to close connection, already closed.
		return
	}
	go s.handleChannels(channels, handlerSSHConnection)
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

func (s *server) handleChannels(channels <-chan ssh.NewChannel, connection SSHConnectionHandler) {
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
		go s.handleSessionChannel(channelID, newChannel, connection)
	}
}

type envRequestPayload struct {
	name  string
	value string
}

type execRequestPayload struct {
	exec string
}

type ptyRequestPayload struct {
	term     string
	columns  uint32
	rows     uint32
	width    uint32
	height   uint32
	modelist []byte
}

type shellRequestPayload struct {
}

type signalRequestPayload struct {
	signal string
}

type subsystemRequestPayload struct {
	subsystem string
}

type windowRequestPayload struct {
	columns uint32
	rows    uint32
	width   uint32
	height  uint32
}

type exitStatusPayload struct {
	exitStatus ExitStatus
}

type requestType string

const (
	requestTypeEnv       requestType = "env"
	requestTypePty       requestType = "pty"
	requestTypeShell     requestType = "shell"
	requestTypeExec      requestType = "exec"
	requestTypeSubsystem requestType = "subsystem"
	requestTypeWindow    requestType = "window-change"
	requestTypeSignal    requestType = "signal"
)

func (s *server) handleSessionChannel(channelID uint64, newChannel ssh.NewChannel, connection SSHConnectionHandler) {
	handlerChannel, rejection := connection.OnSessionChannel(channelID, newChannel.ExtraData())
	if rejection != nil {
		if err := newChannel.Reject(rejection.Reason(), rejection.Message()); err != nil {
			s.logger.Debugf("failed to send session channel rejection", err)
		}
		return
	}
	channel, requests, err := newChannel.Accept()
	if err != nil {
		s.logger.Debugf("failed to accept session channel (%v)", err)
		return
	}
	nextRequestID := uint64(0)
	for {
		request, ok := <-requests
		if !ok {
			break
		}
		requestID := nextRequestID
		nextRequestID++
		go s.handleChannelRequest(requestID, request, channel, handlerChannel)
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

func (s *server) handleChannelRequest(requestID uint64, request *ssh.Request, sshChannel ssh.Channel, sessionChannel SessionChannelHandler) {
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
	onExit := func(exitCode ExitStatus) {
		if _, err := sshChannel.SendRequest(
			"exit-status",
			false,
			ssh.Marshal(exitStatusPayload{
				exitStatus: exitCode,
			})); err != nil {
			s.logger.Debugf("failed to send exit status to client (%v)", err)
		}
		if err := sshChannel.Close(); err != nil {
			s.logger.Debugf("failed to close SSH channel (%v)", err)
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
		sshChannel,
		sessionChannel,
		onExit,
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
	channel ssh.Channel,
	sessionChannel SessionChannelHandler,
	onExit func(exitCode ExitStatus),
) error {
	switch requestType {
	case requestTypeEnv:
		return s.onEnvRequest(requestID, sessionChannel, payload)
	case requestTypePty:
		return s.onPtyRequest(requestID, sessionChannel, payload)
	case requestTypeShell:
		return s.onShell(requestID, sessionChannel, channel, onExit)
	case requestTypeExec:
		return s.onExec(requestID, sessionChannel, payload, channel, onExit)
	case requestTypeSubsystem:
		return s.onSubsystem(requestID, sessionChannel, payload, channel, onExit)
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
		payload.(envRequestPayload).name,
		payload.(envRequestPayload).value,
	)
}

func (s *server) onPtyRequest(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnPtyRequest(
		requestID,
		payload.(ptyRequestPayload).term,
		payload.(ptyRequestPayload).columns,
		payload.(ptyRequestPayload).rows,
		payload.(ptyRequestPayload).width,
		payload.(ptyRequestPayload).height,
		payload.(ptyRequestPayload).modelist,
	)
}

func (s *server) onShell(requestID uint64, sessionChannel SessionChannelHandler, channel ssh.Channel, onExit func(exitCode ExitStatus)) error {
	return sessionChannel.OnShell(
		requestID,
		channel,
		channel,
		channel.Stderr(),
		onExit,
	)
}

func (s *server) onExec(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}, channel ssh.Channel, onExit func(exitCode ExitStatus)) error {
	return sessionChannel.OnExecRequest(
		requestID,
		payload.(execRequestPayload).exec,
		channel,
		channel,
		channel.Stderr(),
		onExit,
	)
}

func (s *server) onSignal(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnSignal(
		requestID,
		payload.(signalRequestPayload).signal,
	)
}

func (s *server) onSubsystem(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}, channel ssh.Channel, onExit func(exitCode ExitStatus)) error {
	return sessionChannel.OnSubsystem(
		requestID,
		payload.(subsystemRequestPayload).subsystem,
		channel,
		channel,
		channel.Stderr(),
		onExit,
	)
}

func (s *server) onChannel(requestID uint64, sessionChannel SessionChannelHandler, payload interface{}) error {
	return sessionChannel.OnWindow(
		requestID,
		payload.(windowRequestPayload).columns,
		payload.(windowRequestPayload).rows,
		payload.(windowRequestPayload).width,
		payload.(windowRequestPayload).height,
	)
}
