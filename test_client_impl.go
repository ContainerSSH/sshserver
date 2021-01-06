package sshserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

type testClient struct {
	server  string
	hostKey []byte
	user    *TestUser
}

func (t *testClient) Connect() (TestClientConnection, error) {
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
}

func (t *testClientConnection) MustSession() TestClientSession {
	session, err := t.Session()
	if err != nil {
		panic(err)
	}
	return session
}

func (t *testClientConnection) Session() (TestClientSession, error) {
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
		session:  session,
		stdin:    stdin,
		stdout:   stdout,
		stderr:   stderr,
		exitCode: -1,
	}, nil
}

func (t *testClientConnection) Close() error {
	return t.sshConnection.Close()
}

type testClientSession struct {
	session  *ssh.Session
	stdin    *syncContextPipe
	stderr   *syncContextPipe
	stdout   *syncContextPipe
	exitCode int
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
	return t.session.Setenv(name, value)
}

func (t *testClientSession) Window(cols int, rows int) error {
	return t.session.WindowChange(cols, rows)
}

func (t *testClientSession) RequestPTY(term string, cols int, rows int) error {
	return t.session.RequestPty(term, cols, rows, ssh.TerminalModes{})
}

func (t *testClientSession) Shell() error {
	return t.session.Shell()
}

func (t *testClientSession) Exec(program string) error {
	return t.session.Run(program)
}

func (t *testClientSession) Subsystem(name string) error {
	return t.session.RequestSubsystem(name)
}

func (t *testClientSession) Write(data []byte) (int, error) {
	return t.stdin.Write(data)
}

func (t *testClientSession) WriteCtx(ctx context.Context, data []byte) (int, error) {
	return t.stdin.WriteCtx(ctx, data)
}

func (t *testClientSession) Read(data []byte) (int, error) {
	return t.stdout.Read(data)
}

func (t *testClientSession) ReadCtx(ctx context.Context, data []byte) (int, error) {
	return t.stdout.ReadCtx(ctx, data)
}

func (t *testClientSession) WaitForStdout(ctx context.Context, data []byte) error {
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
				bufIndex++
			}
		}
		if bytes.Equal(ringBuffer, data) {
			return nil
		}
	}
}

func (t *testClientSession) Stderr() io.Reader {
	return t.stderr
}

func (t *testClientSession) Wait() error {
	err := t.session.Wait()
	exitErr := &ssh.ExitError{}
	if errors.As(err, &exitErr) {
		t.exitCode = exitErr.ExitStatus()
		return nil
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
