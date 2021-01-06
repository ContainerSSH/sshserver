package sshserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"

	"github.com/containerssh/unixutils"
)

// NewTestHandler creates a handler that can be used for testing purposes. It does not authenticate, that can be done
// using the NewTestAuthenticationHandler
func NewTestHandler() Handler {
	return &testHandler{}
}

// testHandler is a handler implementation that fakes a "real" backend.
type testHandler struct {
	AbstractHandler

	shutdown bool
}

func (t *testHandler) OnShutdown(_ context.Context) {
	t.shutdown = true
}

func (t *testHandler) OnNetworkConnection(client net.TCPAddr, connectionID string) (NetworkConnectionHandler, error) {
	return &testNetworkHandler{
		client:       client,
		connectionID: connectionID,
		rootHandler:  t,
	}, nil
}

type testNetworkHandler struct {
	AbstractNetworkConnectionHandler

	rootHandler  *testHandler
	client       net.TCPAddr
	connectionID string
	shutdown     bool
}

func (t *testNetworkHandler) OnHandshakeSuccess(username string) (
	connection SSHConnectionHandler,
	failureReason error,
) {
	return &testSSHHandler{
		rootHandler:    t.rootHandler,
		networkHandler: t,
		username:       username,
	}, nil
}

func (t *testNetworkHandler) OnShutdown(_ context.Context) {
	t.shutdown = true
}

type testSSHHandler struct {
	AbstractSSHConnectionHandler

	rootHandler    *testHandler
	networkHandler *testNetworkHandler
	username       string
	shutdown       bool
}

func (t *testSSHHandler) OnSessionChannel(_ uint64, _ []byte) (
	channel SessionChannelHandler,
	failureReason ChannelRejection,
) {
	return &testSessionChannel{
		env:    map[string]string{},
		exited: make(chan struct{}),
		exit:   &sync.Once{},
	}, nil
}

func (t *testSSHHandler) OnShutdown(_ context.Context) {
	t.shutdown = true
}

type testSessionChannel struct {
	AbstractSessionChannelHandler

	env     map[string]string
	pty     bool
	rows    uint32
	columns uint32
	running bool
	term    bool
	stdin   io.ReadCloser
	stdout  io.WriteCloser
	exited  chan struct{}
	exit    *sync.Once
	onExit  func(exitStatus ExitStatus)
}

func (t *testSessionChannel) OnEnvRequest(_ uint64, name string, value string) error {
	if t.running {
		return errors.New("cannot set env variable to an already running program")
	}
	t.env[name] = value
	return nil
}

func (t *testSessionChannel) OnPtyRequest(
	_ uint64,
	term string,
	columns uint32,
	rows uint32,
	_ uint32,
	_ uint32,
	_ []byte,
) error {
	if t.running {
		return errors.New("cannot set PTY for an already running program")
	}
	t.pty = true
	t.env["TERM"] = term
	t.rows = rows
	t.columns = columns
	return nil
}

func (t *testSessionChannel) OnExecRequest(
	_ uint64,
	program string,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	onExit func(exitStatus ExitStatus),
) error {
	if t.running {
		return errors.New("program already running")
	}
	argv, err := unixutils.ParseCMD(program)
	if err != nil {
		return err
	}
	t.running = true
	t.onExit = onExit
	t.stdin = stdin.(io.ReadCloser)
	t.stdout = stdout.(io.WriteCloser)
	onExit = t.wrapOnExit(onExit)
	go func() {
		err := t.run(argv, stdout, stderr, true)
		if err != nil {
			onExit(1)
		} else {
			onExit(0)
		}
	}()
	return nil
}

func (t *testSessionChannel) wrapOnExit(onExit func(exitStatus ExitStatus)) func(exitStatus ExitStatus) {
	return func(exitStatus ExitStatus) {
		select {
		case t.exited <- struct{}{}:
		default:
		}
		t.exit.Do(func() {
			onExit(exitStatus)
		})
	}
}

func (t *testSessionChannel) OnShell(
	_ uint64,
	stdin io.Reader,
	stdout io.Writer,
	stderr io.Writer,
	onExit func(exitStatus ExitStatus),
) error {
	if t.running {
		return errors.New("program already running")
	}
	t.onExit = onExit
	t.running = true
	t.stdin = stdin.(io.ReadCloser)
	t.stdout = stdout.(io.WriteCloser)
	onExit = t.wrapOnExit(onExit)
	go func() {
		for {
			if t.pty {
				_, err := stdout.Write([]byte("> "))
				if err != nil {
					onExit(1)
					return
				}
			}
			command, done := t.readCommand(stdin, stdout, onExit)
			if done {
				return
			}
			argv, err := unixutils.ParseCMD(command)
			if err != nil {
				_, _ = stderr.Write([]byte(err.Error()))
				onExit(1)
				return
			}
			if t.pty {
				// If the terminal is interactive everything goes to stdout.
				stderr = stdout
			}
			if argv[0] == "exit" {
				onExit(0)
				return
			}
			if err := t.run(argv, stdout, stderr, false); err != nil {
				onExit(1)
				return
			}
		}
	}()
	return nil
}

func (t *testSessionChannel) readCommand(
	stdin io.Reader,
	stdout io.Writer,
	onExit func(exitStatus ExitStatus),
) (
	string,
	bool,
) {
	cmd := bytes.Buffer{}
	for {
		b := make([]byte, 1)
		n, err := stdin.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				onExit(0)
				return "", true
			} else {
				onExit(1)
				return "", true
			}
		}
		if n == 0 {
			onExit(0)
			return "", true
		}
		if t.term {
			onExit(0)
			return "", true
		}
		if _, err := stdout.Write(b); err != nil {
			if errors.Is(err, io.EOF) {
				onExit(0)
				return "", true
			} else {
				onExit(1)
				return "", true
			}
		}
		cmd.Write(b)
		if b[0] == '\n' {
			break
		}
	}
	command := strings.TrimSpace(cmd.String())
	return command, false
}

func (t *testSessionChannel) run(argv []string, stdout io.Writer, stderr io.Writer, exitWithError bool) (err error) {
	switch argv[0] {
	case "echo":
		_, err = stdout.Write([]byte(strings.Join(argv[1:], " ") + "\n"))
	case "tput":
		if len(argv) > 2 || (argv[1] != "cols" && argv[1] != "rows") {
			_, err = stderr.Write([]byte("Usage: tput [rows|cols]"))
			if exitWithError {
				return fmt.Errorf("usage: tput [rows|cols]")
			}
		} else if !t.pty {
			_, err = stderr.Write([]byte("Stdout is not a TTY"))
			if exitWithError {
				return fmt.Errorf("usage: tput [rows|cols]")
			}
		} else {
			switch argv[1] {
			case "cols":
				_, err = stdout.Write([]byte(fmt.Sprintf("%d\n", t.columns)))
			case "rows":
				_, err = stdout.Write([]byte(fmt.Sprintf("%d\n", t.rows)))
			}
		}
	default:
		_, err = stderr.Write([]byte(fmt.Sprintf("unknown program: %s", argv[0])))
		if exitWithError {
			return fmt.Errorf("unknown program: %s", argv[0])
		}
	}
	return err
}

func (t *testSessionChannel) OnSignal(
	_ uint64,
	signal string,
) error {
	if !t.running {
		return errors.New("program not running")
	}
	if signal != "TERM" {
		return fmt.Errorf("signal type not supported")
	}

	// We cannot stop the process in a sane way due to the stupid SSH API, so let's instead close the channel.
	_ = t.stdin.Close()

	return nil
}

func (t *testSessionChannel) OnWindow(
	_ uint64,
	columns uint32,
	rows uint32,
	_ uint32,
	_ uint32,
) error {
	if !t.running {
		return errors.New("program not running")
	}
	if !t.pty {
		return errors.New("not a PTY session")
	}
	t.rows = rows
	t.columns = columns
	return nil
}

func (t *testSessionChannel) OnShutdown(_ context.Context) {
	if t.running {
		//Simulate exit
		_ = t.OnSignal(0, "TERM")
		t.exit.Do(
			func() {
				t.onExit(0)
			})
	}
}
