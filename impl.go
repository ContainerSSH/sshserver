package sshserver

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/containerssh/log"
	"golang.org/x/crypto/ssh"
)

type server struct {
	cfg             Config
	logger          log.Logger
	ctx             context.Context
	shutdownContext context.Context
	cancelFunc      context.CancelFunc
	handler         Handler
	listenSocket    net.Listener
	wg              *sync.WaitGroup
	lock            *sync.Mutex
	clientSockets   map[*ssh.ServerConn]bool
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
	}
	s.cancelFunc()
	s.shutdownContext = shutdownContext
	s.lock.Unlock()

	done := make(chan bool, 1)
	go func() {
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
			s.lock.Unlock()
		case <-done:
		}
	}()
	s.wg.Wait()
	<-done
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
	defer func() {
		if s.listenSocket != nil {
			if err := netListener.Close(); err != nil {
				s.logger.Warningf("failed to close listen socket (%v)", err)
			}
		}
	}()
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
	handlerNetworkConnection NetworkConnection,
) func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
		authResponse, err := handlerNetworkConnection.OnAuthPubKey(conn.User(), password)
		if err != nil {
			s.logger.Warningf("error while trying to authenticate user %s (%v)", conn.User(), err)
			return nil, fmt.Errorf("authentication currently unavailable")
		}
		switch authResponse {
		case AuthResponseSuccess:
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			return nil, fmt.Errorf("authentication failed")
		case AuthResponseUnavailable:
			s.logger.Warningf("authentication backend currently unavailable.")
			return nil, fmt.Errorf("authentication currently unavailable")
		}
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) createPubKeyAuthenticator(
	handlerNetworkConnection NetworkConnection,
) func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	return func(conn ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
		authResponse, err := handlerNetworkConnection.OnAuthPubKey(conn.User(), pubKey.Marshal())
		if err != nil {
			s.logger.Warningf("error while trying to authenticate user %s (%v)", conn.User(), err)
			return nil, fmt.Errorf("authentication currently unavailable")
		}
		switch authResponse {
		case AuthResponseSuccess:
			return &ssh.Permissions{}, nil
		case AuthResponseFailure:
			return nil, fmt.Errorf("authentication failed")
		case AuthResponseUnavailable:
			s.logger.Warningf("authentication backend currently unavailable.")
			return nil, fmt.Errorf("authentication currently unavailable")
		}
		return nil, fmt.Errorf("authentication currently unavailable")
	}
}

func (s *server) createConfiguration(handlerNetworkConnection NetworkConnection) *ssh.ServerConfig {
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
	handlerNetworkConnection, err := s.handler.OnNetworkConnection(conn.RemoteAddr())
	if err != nil {
		s.logger.Infoe(err)
		_ = conn.Close()
		return
	}
	s.logger.Debugf("client connected: %s", conn.RemoteAddr().String())

	sshConn, channels, globalRequests, err := ssh.NewServerConn(conn, s.createConfiguration(handlerNetworkConnection))
	if err != nil {
		s.logger.Debugf("SSH handshake failed for %s (%v)", conn.RemoteAddr().String(), err)
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
		s.logger.Debugf("client disconnected: %s", conn.RemoteAddr().String())
		handlerNetworkConnection.OnDisconnect()
		s.wg.Done()
	}()
	handlerSSHConnection, failureReason := handlerNetworkConnection.OnHandshakeSuccess()
	if failureReason != nil {
		s.logger.Debugf("handshake success handler returned with error (%v)", err)
		if err := sshConn.Close(); err != nil {
			s.logger.Debugf("failed to close SSH connection to %s (%v)", sshConn.RemoteAddr().String(), err)
			return
		}
	}
	go s.handleChannels(channels, handlerSSHConnection)
	go s.handleGlobalRequests(globalRequests, handlerSSHConnection)
}

func (s *server) handleGlobalRequests(requests <-chan *ssh.Request, connection SSHConnection) {
	for {
		request, ok := <-requests
		if !ok {
			break
		}
		connection.OnUnsupportedGlobalRequest(request.Type, request.Payload)
		if request.WantReply {
			if err := request.Reply(false, []byte("request type not supported")); err != nil {
				s.logger.Debugf("failed to send reply to global request type %s (%v)", request.Type, err)
			}
		}
	}
}

func (s *server) handleChannels(channels <-chan ssh.NewChannel, connection SSHConnection) {
	for {
		newChannel, ok := <-channels
		if !ok {
			break
		}
		if newChannel.ChannelType() != "session" {
			connection.OnUnsupportedChannel(newChannel.ChannelType(), newChannel.ExtraData())
			if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
				s.logger.Debugf("failed to send channel rejection for channel type %s", newChannel.ChannelType())
			}
			continue
		}
		go s.handleSessionChannel(newChannel, connection)
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
	exitStatus uint32
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

var requestPayloadFormats = map[requestType]interface{}{
	requestTypeEnv:       envRequestPayload{},
	requestTypePty:       ptyRequestPayload{},
	requestTypeShell:     shellRequestPayload{},
	requestTypeExec:      execRequestPayload{},
	requestTypeSubsystem: subsystemRequestPayload{},
	requestTypeWindow:    windowRequestPayload{},
	requestTypeSignal:    signalRequestPayload{},
}

func (s *server) handleSessionChannel(newChannel ssh.NewChannel, connection SSHConnection) {
	handlerChannel, rejection := connection.OnSessionChannel(newChannel.ExtraData())
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
	for {
		request, ok := <-requests
		if !ok {
			break
		}
		go s.handleChannelRequest(request, channel, handlerChannel)
	}
}

func (s *server) handleChannelRequest(request *ssh.Request, sshChannel ssh.Channel, sessionChannel SessionChannel) {
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
	onExit := func(exitCode uint32) {
		if _, err := sshChannel.SendRequest(
			"exit-status",
			false,
			ssh.Marshal(exitStatusPayload{
				exitStatus: exitCode,
			})); err != nil {
			s.logger.Debugf("failed to send exit status to client (%v)", err)
		}
	}
	payload, ok := requestPayloadFormats[requestType(request.Type)]
	if !ok {
		sessionChannel.OnUnsupportedChannelRequest(request.Type, request.Payload)
		reply(false, fmt.Sprintf("unsupported request type: %s", request.Type), nil)
		return
	}
	if err := ssh.Unmarshal(request.Payload, &payload); err != nil {
		s.logger.Debugf("failed to unmarshal %s request payload %v (%v)", request.Type, request.Payload, err)
		sessionChannel.OnFailedDecodeChannelRequest(request.Type, request.Payload, err)
		reply(false, "failed to unmarshal payload", nil)
		return
	}
	if err := s.handleDecodedChannelRequest(
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
	requestType requestType,
	payload interface{},
	channel ssh.Channel,
	sessionChannel SessionChannel,
	onExit func(exitCode uint32),
) error {
	switch requestType {
	case requestTypeEnv:
		return sessionChannel.OnEnvRequest(
			payload.(envRequestPayload).name,
			payload.(envRequestPayload).value,
		)
	case requestTypePty:
		return sessionChannel.OnPtyRequest(
			payload.(ptyRequestPayload).term,
			payload.(ptyRequestPayload).columns,
			payload.(ptyRequestPayload).rows,
			payload.(ptyRequestPayload).width,
			payload.(ptyRequestPayload).height,
			payload.(ptyRequestPayload).modelist,
		)
	case requestTypeShell:
		return sessionChannel.OnShell(
			channel,
			channel,
			channel.Stderr(),
			onExit,
		)
	case requestTypeExec:
		return sessionChannel.OnExecRequest(
			payload.(execRequestPayload).exec,
			channel,
			channel,
			channel.Stderr(),
			onExit,
		)
	case requestTypeSubsystem:
		return sessionChannel.OnSubsystem(
			payload.(subsystemRequestPayload).subsystem,
			channel,
			channel,
			channel.Stderr(),
			onExit,
		)
	case requestTypeWindow:
		return sessionChannel.OnWindow(
			payload.(windowRequestPayload).columns,
			payload.(windowRequestPayload).rows,
			payload.(windowRequestPayload).width,
			payload.(windowRequestPayload).height,
		)
	case requestTypeSignal:
		return sessionChannel.OnSignal(payload.(signalRequestPayload).signal)
	}
	return nil
}
