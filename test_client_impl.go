package sshserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	time "time"

	"github.com/containerssh/log"
	"golang.org/x/crypto/ssh"
)

type testClient struct {
	server  string
	hostKey []byte
	user    *TestUser
	logger  log.Logger
}

func (t *testClient) Connect() (TestClientConnection, error) {
	t.logger.Debugf("Connecting SSH server...")
	sshConfig := &ssh.ClientConfig{
		User: t.user.Username(),
		Auth: t.user.getAuthMethods(),
	}
	sshConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), t.hostKey) {
			return nil
		}
		return fmt.Errorf("invalid host")
	}
	sshConnection, err := ssh.Dial("tcp", t.server, sshConfig)
	if err != nil {
		return nil, fmt.Errorf("handshake failed (%w)", err)
	}

	return &testClientConnection{
		logger:        t.logger,
		sshConnection: sshConnection,
	}, nil
}

func (t *testClient) MustConnect() TestClientConnection {
	connection, err := t.Connect()
	if err != nil {
		panic(err)
	}
	return connection
}

type testClientConnection struct {
	sshConnection *ssh.Client
	logger        log.Logger
}

func (t *testClientConnection) MustSession() TestClientSession {
	session, err := t.Session()
	if err != nil {
		panic(err)
	}
	return session
}

func (t *testClientConnection) Session() (TestClientSession, error) {
	t.logger.Debugf("Opening session channel..")
	session, err := t.sshConnection.NewSession()
	if err != nil {
		return nil, err
	}
	stdin := newSyncContextPipe()
	stdout := newSyncContextPipe()
	stderr := newSyncContextPipe()
	session.Stdin = stdin
	session.Stdout = stdout
	session.Stderr = stderr

	return &testClientSession{
		logger:   t.logger,
		session:  session,
		stdin:    stdin,
		stdout:   stdout,
		stderr:   stderr,
		exitCode: -1,
	}, nil
}

func (t *testClientConnection) Close() error {
	t.logger.Debugf("Closing connection...")
	return t.sshConnection.Close()
}

type testClientSession struct {
	session  *ssh.Session
	stdin    *syncContextPipe
	stderr   *syncContextPipe
	stdout   *syncContextPipe
	exitCode int
	logger   log.Logger
	pty      bool
}

func (t *testClientSession) ReadRemaining() {
	t.logger.Debugf("Reading reaining bytes from stdout...")
	for {
		data := make([]byte, 1024)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := t.stdout.ReadCtx(ctx, data)
		if err != nil {
			return
		}
	}
}

func (t *testClientSession) ReadRemainingStderr() {
	t.logger.Debugf("Reading reaining bytes from stderr...")
	for {
		data := make([]byte, 1024)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err := t.stderr.ReadCtx(ctx, data)
		if err != nil {
			return
		}
	}
}

func (t *testClientSession) Type(data []byte) error {
	t.logger.Debugf("Typing on stdin with sleep and readback: %s", data)
	for _, b := range data {
		_, err := t.Write([]byte{b})
		if err != nil {
			return err
		}
		readBack := make([]byte, 1)
		n, err := t.Read(readBack)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("failed to read back typed byte")
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.logger.Debugf("Typing done.")
	return nil
}

func (t *testClientSession) Signal(signal string) error {
	t.logger.Debugf("Sending %s signal to process...", signal)
	return t.session.Signal(ssh.Signal(signal))
}

func (t *testClientSession) MustSignal(signal string) {
	err := t.Signal(signal)
	if err != nil {
		panic(err)
	}
}

func (t *testClientSession) MustSetEnv(name string, value string) {
	if err := t.SetEnv(name, value); err != nil {
		panic(err)
	}
}

func (t *testClientSession) MustWindow(cols int, rows int) {
	if err := t.Window(cols, rows); err != nil {
		panic(err)
	}
}

func (t *testClientSession) MustRequestPTY(term string, cols int, rows int) {
	if err := t.RequestPTY(term, cols, rows); err != nil {
		panic(err)
	}
}

func (t *testClientSession) MustShell() {
	if err := t.Shell(); err != nil {
		panic(err)
	}
}

func (t *testClientSession) MustExec(program string) {
	if err := t.Exec(program); err != nil {
		panic(err)
	}
}

func (t *testClientSession) MustSubsystem(name string) {
	if err := t.Subsystem(name); err != nil {
		panic(err)
	}
}

func (t *testClientSession) SetEnv(name string, value string) error {
	t.logger.Debugf("Setting env variable %s=%s...", name, value)
	return t.session.Setenv(name, value)
}

func (t *testClientSession) Window(cols int, rows int) error {
	t.logger.Debugf("Changing window to cols %d rows %d...", cols, rows)
	return t.session.WindowChange(rows, cols)
}

func (t *testClientSession) RequestPTY(term string, cols int, rows int) error {
	t.logger.Debugf("Requesting PTY for term %s cols %d rows %d...", term, cols, rows)
	if err := t.session.RequestPty(term, rows, cols, ssh.TerminalModes{}); err != nil {
		return err
	}
	t.pty = true
	return nil
}

func (t *testClientSession) Shell() error {
	t.logger.Debugf("Executing shell...")
	if t.pty {
		t.session.Stderr = nil
	}
	return t.session.Shell()
}

func (t *testClientSession) Exec(program string) error {
	t.logger.Debugf("Executing program '%s'...", program)
	if t.pty {
		t.session.Stderr = nil
	}
	return t.session.Start(program)
}

func (t *testClientSession) Subsystem(name string) error {
	t.logger.Debugf("Requesting subsystem %s...", name)
	if t.pty {
		t.session.Stderr = nil
	}
	return t.session.RequestSubsystem(name)
}

func (t *testClientSession) Write(data []byte) (int, error) {
	t.logger.Debugf("Writing to stdin: %s", data)
	return t.stdin.Write(data)
}

func (t *testClientSession) WriteCtx(ctx context.Context, data []byte) (int, error) {
	t.logger.Debugf("Writing to stdin: %s", data)
	return t.stdin.WriteCtx(ctx, data)
}

func (t *testClientSession) Read(data []byte) (int, error) {
	t.logger.Debugf("Reading %d bytes from stdout...", len(data))
	return t.stdout.Read(data)
}

func (t *testClientSession) ReadCtx(ctx context.Context, data []byte) (int, error) {
	t.logger.Debugf("Reading %d bytes from stdout...", len(data))
	return t.stdout.ReadCtx(ctx, data)
}

func (t *testClientSession) WaitForStdout(ctx context.Context, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	t.logger.Debugf("Waiting for the following string on stdout: %s", data)
	if len(data) == 0 {
		return nil
	}
	ringBuffer := make([]byte, len(data))
	bufIndex := 0
	for {
		buf := make([]byte, 1)
		n, err := t.stdout.ReadCtx(ctx, buf)
		if err != nil {
			return err
		}
		if n > 0 {
			if bufIndex == len(data) {
				ringBuffer = append(ringBuffer[1:], buf[0])
			} else {
				ringBuffer[bufIndex] = buf[0]
				bufIndex += n
			}
		}
		t.logger.Debugf("Ringbuffer currently contains the following %d bytes: %s", bufIndex, ringBuffer[:bufIndex])
		if bytes.Equal(ringBuffer[:bufIndex], data) {
			return nil
		}
	}
}

func (t *testClientSession) Stderr() io.Reader {
	return t.stderr
}

func (t *testClientSession) Wait() error {
	t.logger.Debugf("Waiting for session to finish.")
	t.ReadRemaining()
	t.ReadRemainingStderr()
	err := t.session.Wait()
	if err != nil {
		exitErr := &ssh.ExitError{}
		if errors.As(err, &exitErr) {
			t.exitCode = exitErr.ExitStatus()
			return nil
		}
	} else {
		t.exitCode = 0
	}
	return err
}

func (t *testClientSession) ExitCode() int {
	return t.exitCode
}

func (t *testClientSession) Close() error {
	return t.session.Close()
}

func newSyncContextPipe() *syncContextPipe {
	return &syncContextPipe{
		make(chan byte),
		false,
		&sync.Mutex{},
	}
}

// syncContextPipe is a pipe that is able to handle timeouts via contexts.
type syncContextPipe struct {
	byteChannel chan byte
	closed      bool
	lock        *sync.Mutex
}

func (c *syncContextPipe) Write(data []byte) (int, error) {
	return c.WriteCtx(context.Background(), data)
}

func (c *syncContextPipe) Read(data []byte) (int, error) {
	return c.ReadCtx(context.Background(), data)
}

func (c *syncContextPipe) Close() error {
	c.lock.Lock()
	defer c.lock.Unlock()
	if c.closed {
		return io.EOF
	}
	c.closed = true
	return nil
}

func (c *syncContextPipe) WriteCtx(ctx context.Context, data []byte) (int, error) {
	for _, b := range data {
		select {
		case c.byteChannel <- b:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}
	return len(data), nil
}

func (c *syncContextPipe) ReadCtx(ctx context.Context, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	i := 0
	var b byte
	select {
	case b = <-c.byteChannel:
		data[i] = b
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	i++
	for {
		if i == len(data) {
			return i, nil
		}
		select {
		case b = <-c.byteChannel:
			data[i] = b
		case <-ctx.Done():
			return i, ctx.Err()
		default:
			return i, nil
		}
	}
}
