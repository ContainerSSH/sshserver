package sshserver_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/containerssh/log/standard"
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
	logger := standard.New()
	handler := &rejectHandler{}

	server, err := sshserver.New(config, handler, logger)
	if err != nil {
		assert.Fail(t, "failed to create server", err)
		return
	}
	err = server.Run()
	if err == nil {
		assert.Fail(t, "server.Run() did not result in an error")
	} else {
		assert.Equal(t, "rejected", err.Error())
	}
	server.Shutdown(context.Background())
}

func TestAuthFailed(t *testing.T) {
	server := newServerHelper(t, "0.0.0.0:2222", map[string][]byte{
		"foo": []byte("bar"),
	})
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer server.stop()

	sshConfig := &ssh.ClientConfig{
		User: "foo",
		Auth: []ssh.AuthMethod{ssh.Password("invalid")},
	}
	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), hostKey) {
			return nil
		}
		return fmt.Errorf("invalid host")
	}

	sshConnection, err := ssh.Dial("tcp", "0.0.0.0:2222", sshConfig)
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
	server := newServerHelper(t, "127.0.0.1:2222", map[string][]byte{
		"foo": []byte("bar"),
	})
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer server.stop()

	reply, exitStatus, err := shellRequestReply("127.0.0.1:2222", "foo", "bar", hostKey, []byte("Hi"))
	assert.Equal(t, []byte("Hello world!"), reply)
	assert.Equal(t, 0, exitStatus)
	assert.Equal(t, nil, err)
}

func TestSessionError(t *testing.T) {
	server := newServerHelper(t, "127.0.0.1:2222", map[string][]byte{
		"foo": []byte("bar"),
	})
	hostKey, err := server.start()
	if err != nil {
		assert.Fail(t, "failed to start ssh server", err)
		return
	}
	defer server.stop()

	reply, exitStatus, err := shellRequestReply("127.0.0.1:2222", "foo", "bar", hostKey, []byte("Ho"))
	assert.Equal(t, 1, exitStatus)
	assert.Equal(t, []byte{}, reply)
	assert.Equal(t, nil, err)
}

//endregion

//region Helper

func shellRequestReply(host string, user string, password string, hostKey []byte, request []byte) (reply []byte, exitStatus int, err error) {
	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{ssh.Password(password)},
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

	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, -1, fmt.Errorf("failed to request stdin (%w)", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, -1, fmt.Errorf("failed to request stdout (%w)", err)
	}

	if err := session.Shell(); err != nil {
		return nil, -1, fmt.Errorf("failed to request shell (%w)", err)
	}
	if _, err := stdin.Write(request); err != nil {
		return nil, -1, fmt.Errorf("failed to write to shell (%w)", err)
	}
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

func newServerHelper(t *testing.T, listen string, passwords map[string][]byte) *serverHelper {
	return &serverHelper{
		t:         t,
		listen:    listen,
		passwords: passwords,
	}
}

type serverHelper struct {
	t         *testing.T
	server    sshserver.Server
	passwords map[string][]byte
	listen    string
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
	hostKey = config.HostKeys[0].PublicKey().Marshal()
	logger := standard.New()
	readyChannel := make(chan bool, 1)
	errChannel := make(chan error, 1)
	handler := newFullHandler(
		readyChannel,
		h.passwords,
		map[string][]byte{},
	)
	server, err := sshserver.New(config, handler, logger)
	if err != nil {
		return hostKey, err
	}
	go func() {
		err = server.Run()
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
	if h.server != nil {
		h.server.Shutdown(context.Background())
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

func (r *rejectHandler) OnNetworkConnection(_ *net.TCPAddr, _ []byte) (sshserver.NetworkConnectionHandler, error) {
	return nil, fmt.Errorf("not implemented")
}

//endregion

//region Full

func newFullHandler(readyChannel chan bool, passwords map[string][]byte, pubKeys map[string][]byte) sshserver.Handler {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &fullHandler{
		ctx:        ctx,
		cancelFunc: cancelFunc,
		ready:      readyChannel,
		passwords:  passwords,
		pubKeys:    pubKeys,
	}
}

//region Handler
type fullHandler struct {
	ctx             context.Context
	shutdownContext context.Context
	cancelFunc      context.CancelFunc
	passwords       map[string][]byte
	pubKeys         map[string][]byte
	ready           chan bool
}

func (f *fullHandler) OnReady() error {
	f.ready <- true
	return nil
}

func (f *fullHandler) OnShutdown(shutdownContext context.Context) {
	f.shutdownContext = shutdownContext
}

func (f *fullHandler) OnNetworkConnection(_ *net.TCPAddr, _ []byte) (sshserver.NetworkConnectionHandler, error) {
	return &fullNetworkConnectionHandler{
		handler: f,
	}, nil
}

//endregion

//region Network connection handler

type fullNetworkConnectionHandler struct {
	handler *fullHandler
}

func (f *fullNetworkConnectionHandler) OnAuthPassword(username string, password []byte) (response sshserver.AuthResponse, reason error) {
	if storedPassword, ok := f.handler.passwords[username]; ok && bytes.Equal(storedPassword, password) {
		return sshserver.AuthResponseSuccess, nil
	}
	return sshserver.AuthResponseFailure, fmt.Errorf("authentication failed")
}

func (f *fullNetworkConnectionHandler) OnAuthPubKey(username string, pubKey []byte) (response sshserver.AuthResponse, reason error) {
	if storedPubKey, ok := f.handler.pubKeys[username]; ok && bytes.Equal(storedPubKey, pubKey) {
		return sshserver.AuthResponseSuccess, nil
	}
	return sshserver.AuthResponseFailure, fmt.Errorf("authentication failed")
}

func (f *fullNetworkConnectionHandler) OnHandshakeFailed(_ error) {

}

func (f *fullNetworkConnectionHandler) OnHandshakeSuccess() (connection sshserver.SSHConnectionHandler, failureReason error) {
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

func (f *fullSSHConnectionHandler) OnUnsupportedGlobalRequest(_ string, _ []byte) {

}

func (f *fullSSHConnectionHandler) OnUnsupportedChannel(_ string, _ []byte) {

}

func (f *fullSSHConnectionHandler) OnSessionChannel(_ []byte) (channel sshserver.SessionChannelHandler, failureReason sshserver.ChannelRejection) {
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
}

func (f *fullSessionChannelHandler) OnUnsupportedChannelRequest(_ string, _ []byte) {
}

func (f *fullSessionChannelHandler) OnFailedDecodeChannelRequest(_ string, _ []byte, _ error) {
}

func (f *fullSessionChannelHandler) OnEnvRequest(name string, value string) error {
	f.env[name] = value
	return nil
}

func (f *fullSessionChannelHandler) OnExecRequest(
	_ string, _ io.Reader, _ io.Writer, _ io.Writer, _ func(exitStatus uint32),
) error {
	return fmt.Errorf("this server does not support exec")
}

func (f *fullSessionChannelHandler) OnPtyRequest(
	_ string, _ uint32, _ uint32, _ uint32, _ uint32, _ []byte,
) error {
	return fmt.Errorf("this server does not support PTY")
}

func (f *fullSessionChannelHandler) OnShell(
	stdin io.Reader, stdout io.Writer, _ io.Writer, onExit func(exitStatus uint32),
) error {
	go func() {
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

func (f *fullSessionChannelHandler) OnSignal(_ string) error {
	return nil
}

func (f *fullSessionChannelHandler) OnSubsystem(
	_ string, _ io.Reader, _ io.Writer, _ io.Writer, _ func(exitStatus uint32),
) error {
	return fmt.Errorf("subsystem not supported")
}

func (f *fullSessionChannelHandler) OnWindow(_ uint32, _ uint32, _ uint32, _ uint32) error {
	return nil
}

//endregion

//endregion

//endregion
