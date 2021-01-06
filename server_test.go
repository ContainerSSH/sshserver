package sshserver_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/containerssh/log"
	"github.com/containerssh/service"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/containerssh/sshserver"
)

//region Tests

func TestReadyRejection(t *testing.T) {
	config := sshserver.DefaultConfig()
	if err := config.GenerateHostKey(); err != nil {
		assert.Fail(t, "failed to generate host key", err)
		return
	}
	logger, err := log.New(
		log.Config{
			Level:  log.LevelDebug,
			Format: log.FormatText,
		},
		"ssh",
		os.Stdout,
	)
	assert.NoError(t, err)
	handler := &rejectHandler{}

	server, err := sshserver.New(config, handler, logger)
	if err != nil {
		assert.Fail(t, "failed to create server", err)
		return
	}
	lifecycle := service.NewLifecycle(server)
	err = lifecycle.Run()
	if err == nil {
		assert.Fail(t, "server.Run() did not result in an error")
	} else {
		assert.Equal(t, "rejected", err.Error())
	}
	lifecycle.Stop(context.Background())
}

func TestAuthFailed(t *testing.T) {
	server := newServerHelper(
		t,
		"127.0.0.1:2222",
		map[string][]byte{
			"foo": []byte("bar"),
		},
		map[string]string{},
	)
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer func() {
		server.stop()
		<-server.shutdownChannel
	}()

	sshConfig := &ssh.ClientConfig{
		User: "foo",
		Auth: []ssh.AuthMethod{ssh.Password("invalid")},
	}
	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		marshaledKey := key.Marshal()
		if bytes.Equal(marshaledKey, hostKey) {
			return nil
		}
		return fmt.Errorf("invalid host")
	}

	sshConnection, err := ssh.Dial("tcp", "127.0.0.1:2222", sshConfig)
	if err != nil {
		if !strings.Contains(err.Error(), "unable to authenticate") {
			assert.Fail(t, "handshake failed for non-auth reasons", err)
		}
	} else {
		_ = sshConnection.Close()
		assert.Fail(t, "authentication succeeded", err)
	}
}

func TestSessionSuccess(t *testing.T) {
	server := newServerHelper(
		t,
		"127.0.0.1:2222",
		map[string][]byte{
			"foo": []byte("bar"),
		},
		map[string]string{},
	)
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer func() {
		server.stop()
		<-server.shutdownChannel
	}()

	reply, exitStatus, err := shellRequestReply(
		"127.0.0.1:2222",
		"foo",
		ssh.Password("bar"),
		hostKey,
		[]byte("Hi"),
		nil,
		nil,
	)
	assert.Equal(t, []byte("Hello world!"), reply)
	assert.Equal(t, 0, exitStatus)
	assert.Equal(t, nil, err)
}

func TestSessionError(t *testing.T) {
	server := newServerHelper(
		t,
		"127.0.0.1:2222",
		map[string][]byte{
			"foo": []byte("bar"),
		},
		map[string]string{},
	)
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer func() {
		server.stop()
		<-server.shutdownChannel
	}()

	reply, exitStatus, err := shellRequestReply(
		"127.0.0.1:2222",
		"foo",
		ssh.Password("bar"),
		hostKey,
		[]byte("Ho"),
		nil,
		nil,
	)
	assert.Equal(t, 1, exitStatus)
	assert.Equal(t, []byte{}, reply)
	assert.Equal(t, nil, err)
}

func TestPubKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(
		rand.Reader,
		2048,
	)
	assert.Nil(t, err, "failed to generate RSA key (%v)", err)
	signer, err := ssh.NewSignerFromKey(rsaKey)
	assert.Nil(t, err, "failed to create signer (%v)", err)
	publicKey := signer.PublicKey()
	authorizedKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(publicKey)))
	server := newServerHelper(
		t,
		"127.0.0.1:2222",
		map[string][]byte{},
		map[string]string{
			"foo": authorizedKey,
		},
	)
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer func() {
		server.stop()
		<-server.shutdownChannel
	}()

	reply, exitStatus, err := shellRequestReply(
		"127.0.0.1:2222",
		"foo",
		ssh.PublicKeys(signer),
		hostKey,
		[]byte("Hi"),
		nil,
		nil,
	)
	assert.Nil(t, err, "failed to send shell request (%v)", err)
	assert.Equal(t, 0, exitStatus)
	assert.Equal(t, []byte("Hello world!"), reply)
}

func TestExitHandlingOnShutdown(t *testing.T) {
	server := newServerHelper(
		t,
		"127.0.0.1:2222",
		map[string][]byte{
			"foo": []byte("bar"),
		},
		map[string]string{},
	)
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer server.stop()
	shellChan := make(chan struct{})
	responseChan := make(chan struct{})
	server.lifecycle.OnStopping(
		func(s service.Service, l service.Lifecycle, shutdownContext context.Context) {
			responseChan <- struct{}{}
		})
	var reply []byte
	var exitStatus int
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func() {
		defer wg.Done()
		reply, exitStatus, err = shellRequestReply(
			"127.0.0.1:2222",
			"foo",
			ssh.Password("bar"),
			hostKey,
			[]byte("Hi"),
			shellChan,
			responseChan,
		)
		assert.Nil(t, err, "failed to send shell request (%v)", err)
		assert.Equal(t, 0, exitStatus)
		assert.Equal(t, []byte("Hello world!"), reply)
	}()
	<-shellChan
	server.stop()
	wg.Wait()
}

func TestExitHandlingWithExistingConnection(t *testing.T) {

}

//endregion

//region Helper

func shellRequestReply(
	host string,
	user string,
	authMethod ssh.AuthMethod,
	hostKey []byte,
	request []byte,
	onShell chan struct{},
	canSendResponse chan struct{},
) (reply []byte, exitStatus int, err error) {
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{authMethod},
	}
	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), hostKey) {
			return nil
		}
		return fmt.Errorf("invalid host")
	}
	sshConnection, err := ssh.Dial("tcp", host, sshConfig)
	if err != nil {
		return nil, -1, fmt.Errorf("handshake failed (%w)", err)
	}
	defer func() {
		if sshConnection != nil {
			_ = sshConnection.Close()
		}
	}()

	session, err := sshConnection.NewSession()
	if err != nil {
		return nil, -1, fmt.Errorf("new session failed (%w)", err)
	}

	stdin, stdout, err := createPipe(session)
	if err != nil {
		return nil, -1, err
	}

	if err := session.Setenv("TERM", "xterm"); err != nil {
		return nil, -1, err
	}

	if err := session.Shell(); err != nil {
		return nil, -1, fmt.Errorf("failed to request shell (%w)", err)
	}
	if onShell != nil {
		onShell <- struct{}{}
	}
	if canSendResponse != nil {
		<-canSendResponse
	}
	if _, err := stdin.Write(request); err != nil {
		return nil, -1, fmt.Errorf("failed to write to shell (%w)", err)
	}
	return read(stdout, stdin, session)
}

func read(stdout io.Reader, stdin io.WriteCloser, session *ssh.Session) (
	[]byte,
	int,
	error,
) {
	var exitStatus int
	data := make([]byte, 4096)
	n, err := stdout.Read(data)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, -1, fmt.Errorf("failed to read from stdout (%w)", err)
	}
	if err := stdin.Close(); err != nil && !errors.Is(err, io.EOF) {
		return data[:n], -1, fmt.Errorf("failed to close stdin (%w)", err)
	}
	if err := session.Wait(); err != nil {
		exitError := &ssh.ExitError{}
		if errors.As(err, &exitError) {
			exitStatus = exitError.ExitStatus()
		} else {
			return data[:n], -1, fmt.Errorf("failed to wait for exit (%w)", err)
		}
	}
	if err := session.Close(); err != nil && !errors.Is(err, io.EOF) {
		return data[:n], -1, fmt.Errorf("failed to close session (%w)", err)
	}
	return data[:n], exitStatus, nil
}

func createPipe(session *ssh.Session) (io.WriteCloser, io.Reader, error) {
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request stdin (%w)", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request stdout (%w)", err)
	}
	return stdin, stdout, nil
}

func newServerHelper(
	t *testing.T,
	listen string,
	passwords map[string][]byte,
	pubKeys map[string]string,
) *serverHelper {
	return &serverHelper{
		t:               t,
		listen:          listen,
		passwords:       passwords,
		pubKeys:         pubKeys,
		receivedChannel: make(chan struct{}, 1),
	}
}

type serverHelper struct {
	t               *testing.T
	server          sshserver.Server
	lifecycle       service.Lifecycle
	passwords       map[string][]byte
	pubKeys         map[string]string
	listen          string
	shutdownChannel chan struct{}
	receivedChannel chan struct{}
}

func (h *serverHelper) start() (hostKey []byte, err error) {
	if h.server != nil {
		return nil, fmt.Errorf("server already running")
	}
	config := sshserver.DefaultConfig()
	config.Listen = h.listen
	if err := config.GenerateHostKey(); err != nil {
		return nil, err
	}
	private, err := ssh.ParsePrivateKey([]byte(config.HostKeys[0]))
	if err != nil {
		return nil, err
	}
	hostKey = private.PublicKey().Marshal()
	logger, err := log.New(
		log.Config{
			Level:  log.LevelDebug,
			Format: log.FormatText,
		},
		"ssh",
		os.Stdout,
	)
	if err != nil {
		return nil, err
	}
	readyChannel := make(chan struct{}, 1)
	h.shutdownChannel = make(chan struct{}, 1)
	errChannel := make(chan error, 1)
	handler := newFullHandler(
		readyChannel,
		h.shutdownChannel,
		h.passwords,
		h.pubKeys,
	)
	server, err := sshserver.New(config, handler, logger)
	if err != nil {
		return hostKey, err
	}
	lifecycle := service.NewLifecycle(server)
	h.lifecycle = lifecycle
	go func() {
		err = lifecycle.Run()
		if err != nil {
			errChannel <- err
		}
	}()
	//Wait for the server to be ready
	select {
	case err := <-errChannel:
		return hostKey, err
	case <-readyChannel:
	}
	h.server = server
	return hostKey, nil
}

func (h *serverHelper) stop() {
	if h.lifecycle != nil {
		shutdownContext, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
		h.lifecycle.Stop(shutdownContext)
		cancelFunc()
	}
}

//endregion

//region Handlers

//region Rejection

type rejectHandler struct {
}

func (r *rejectHandler) OnReady() error {
	return fmt.Errorf("rejected")
}

func (r *rejectHandler) OnShutdown(_ context.Context) {
}

func (r *rejectHandler) OnNetworkConnection(_ net.TCPAddr, _ string) (sshserver.NetworkConnectionHandler, error) {
	return nil, fmt.Errorf("not implemented")
}

//endregion

//region Full

func newFullHandler(
	readyChannel chan struct{},
	shutdownChannel chan struct{},
	passwords map[string][]byte,
	pubKeys map[string]string,
) sshserver.Handler {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &fullHandler{
		ctx:          ctx,
		cancelFunc:   cancelFunc,
		ready:        readyChannel,
		shutdownDone: shutdownChannel,
		passwords:    passwords,
		pubKeys:      pubKeys,
	}
}

//region Handler
type fullHandler struct {
	ctx             context.Context
	shutdownContext context.Context
	cancelFunc      context.CancelFunc
	passwords       map[string][]byte
	pubKeys         map[string]string
	ready           chan struct{}
	shutdownDone    chan struct{}
}

func (f *fullHandler) OnReady() error {
	f.ready <- struct{}{}
	return nil
}

func (f *fullHandler) OnShutdown(shutdownContext context.Context) {
	f.shutdownContext = shutdownContext
	<-f.shutdownContext.Done()
	f.shutdownDone <- struct{}{}
}

func (f *fullHandler) OnNetworkConnection(_ net.TCPAddr, _ string) (sshserver.NetworkConnectionHandler, error) {
	return &fullNetworkConnectionHandler{
		handler: f,
	}, nil
}

//endregion

//region Network connection handler

type fullNetworkConnectionHandler struct {
	handler *fullHandler
}

func (f *fullNetworkConnectionHandler) OnShutdown(_ context.Context) {

}

func (f *fullNetworkConnectionHandler) OnAuthPassword(username string, password []byte) (response sshserver.AuthResponse, reason error) {
	if storedPassword, ok := f.handler.passwords[username]; ok && bytes.Equal(storedPassword, password) {
		return sshserver.AuthResponseSuccess, nil
	}
	return sshserver.AuthResponseFailure, fmt.Errorf("authentication failed")
}

func (f *fullNetworkConnectionHandler) OnAuthPubKey(username string, pubKey string) (response sshserver.AuthResponse, reason error) {
	if storedPubKey, ok := f.handler.pubKeys[username]; ok && storedPubKey == pubKey {
		return sshserver.AuthResponseSuccess, nil
	}
	return sshserver.AuthResponseFailure, fmt.Errorf("authentication failed")
}

func (f *fullNetworkConnectionHandler) OnHandshakeFailed(_ error) {

}

func (f *fullNetworkConnectionHandler) OnHandshakeSuccess(_ string) (connection sshserver.SSHConnectionHandler, failureReason error) {
	return &fullSSHConnectionHandler{
		handler: f.handler,
	}, nil
}

func (f *fullNetworkConnectionHandler) OnDisconnect() {

}

//endregion

//region SSH connection handler

type fullSSHConnectionHandler struct {
	handler *fullHandler
}

func (f *fullSSHConnectionHandler) OnShutdown(_ context.Context) {

}

func (f *fullSSHConnectionHandler) OnUnsupportedGlobalRequest(_ uint64, _ string, _ []byte) {

}

func (f *fullSSHConnectionHandler) OnUnsupportedChannel(_ uint64, _ string, _ []byte) {

}

func (f *fullSSHConnectionHandler) OnSessionChannel(_ uint64, _ []byte) (channel sshserver.SessionChannelHandler, failureReason sshserver.ChannelRejection) {
	return &fullSessionChannelHandler{
		handler: f.handler,
		env:     map[string]string{},
	}, nil
}

//endregion

//region Session channel handler

type fullSessionChannelHandler struct {
	handler *fullHandler
	env     map[string]string
	stdin   io.Reader
}

func (f *fullSessionChannelHandler) OnUnsupportedChannelRequest(_ uint64, _ string, _ []byte) {
}

func (f *fullSessionChannelHandler) OnFailedDecodeChannelRequest(_ uint64, _ string, _ []byte, _ error) {
}

func (f *fullSessionChannelHandler) OnEnvRequest(_ uint64, name string, value string) error {
	f.env[name] = value
	return nil
}

func (f *fullSessionChannelHandler) OnExecRequest(
	_ uint64, _ string, _ io.Reader, _ io.Writer, _ io.Writer, _ func(exitStatus sshserver.ExitStatus),
) error {
	return fmt.Errorf("this server does not support Exec")
}

func (f *fullSessionChannelHandler) OnPtyRequest(
	_ uint64, _ string, _ uint32, _ uint32, _ uint32, _ uint32, _ []byte,
) error {
	return fmt.Errorf("this server does not support PTY")
}

func (f *fullSessionChannelHandler) OnShell(
	_ uint64, stdin io.Reader, stdout io.Writer, _ io.Writer, onExit func(exitStatus sshserver.ExitStatus),
) error {
	go func() {
		f.stdin = stdin
		data := make([]byte, 4096)
		n, err := stdin.Read(data)
		if err != nil {
			onExit(1)
			return
		}
		if string(data[:n]) != "Hi" {
			onExit(1)
			return
		}
		if _, err := stdout.Write([]byte("Hello world!")); err != nil {
			onExit(1)
			return
		}
		onExit(0)
	}()
	return nil
}

func (f *fullSessionChannelHandler) OnSignal(_ uint64, _ string) error {
	return nil
}

func (f *fullSessionChannelHandler) OnSubsystem(
	_ uint64, _ string, _ io.Reader, _ io.Writer, _ io.Writer, _ func(exitStatus sshserver.ExitStatus),
) error {
	return fmt.Errorf("subsystem not supported")
}

func (f *fullSessionChannelHandler) OnWindow(_ uint64, _ uint32, _ uint32, _ uint32, _ uint32) error {
	return nil
}

func (f *fullSessionChannelHandler) OnShutdown(_ context.Context) {
	if f.stdin != nil {
		// HACK: close stdin to trigger a stop.
		_ = f.stdin.(io.Closer).Close()
	}
}

//endregion

//endregion

//endregion
