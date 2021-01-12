package sshserver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/containerssh/log"
)

// ConformanceTestBackendFactory is a method to creating a network connection handler for testing purposes.
type ConformanceTestBackendFactory = func(logger log.Logger) (NetworkConnectionHandler, error)

// RunConformanceTests runs a suite of conformance tests against the provided backends supporting a standard
// Linux shell.
//goland:noinspection GoUnusedExportedFunction
func RunConformanceTests(t *testing.T, backendFactories map[string]ConformanceTestBackendFactory) {
	t.Parallel()

	for name, factory := range backendFactories {
		n := name
		f := factory
		t.Run(n, func(t *testing.T) {
			t.Parallel()
			testSuite := &conformanceTestSuite{
				backendFactory: f,
			}
			t.Run("singleProgramShouldRun", testSuite.singleProgramShouldRun)
			t.Run("settingEnvVariablesShouldWork", testSuite.settingEnvVariablesShouldWork)
			t.Run("runningInteractiveShellShouldWork", testSuite.runningInteractiveShellShouldWork)
			t.Run("reportingExitCodeShouldWork", testSuite.reportingExitCodeShouldWork)
			t.Run("sendingSignalsShouldWork", testSuite.sendingSignalsShouldWork)
		})
	}
}

type conformanceTestSuite struct {
	backendFactory ConformanceTestBackendFactory
}

func (c *conformanceTestSuite) singleProgramShouldRun(t *testing.T) {
	t.Parallel()
	logger := getLogger(t)

	backend, err := c.backendFactory(logger)
	if err != nil {
		t.Fatal(err)
	}

	user := NewTestUser("test")
	user.RandomPassword()
	srv := NewTestServer(NewTestAuthenticationHandler(
		newHandler(backend),
		user,
	), logger)
	srv.Start()
	defer srv.Stop(10 * time.Second)

	client := NewTestClient(srv.GetListen(), srv.GetHostKey(), user, logger)
	connection, err := client.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = connection.Close()
	}()
	session := connection.MustSession()
	if err := session.Exec("echo \"Hello world!\""); err != nil {
		t.Fatal(err)
	}
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.WaitForStdout(timeout, []byte("Hello world!\n")); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if session.ExitCode() != 0 {
		t.Fatalf("invalid exit code returned: %d", session.ExitCode())
	}
	_ = session.Close()
}

func (c *conformanceTestSuite) settingEnvVariablesShouldWork(t *testing.T) {
	t.Parallel()
	logger := getLogger(t)
	backend, err := c.backendFactory(logger)
	if err != nil {
		t.Fatal(err)
	}

	user := NewTestUser("test")
	user.RandomPassword()
	srv := NewTestServer(NewTestAuthenticationHandler(
		newHandler(backend),
		user,
	), logger)
	srv.Start()
	defer srv.Stop(10 * time.Second)

	client := NewTestClient(srv.GetListen(), srv.GetHostKey(), user, logger)
	connection, err := client.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = connection.Close()
	}()
	session := connection.MustSession()
	if err := session.SetEnv("FOO", "Hello world!"); err != nil {
		t.Fatal(err)
	}
	if err := session.Exec("echo \"$FOO\""); err != nil {
		t.Fatal(err)
	}
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.WaitForStdout(timeout, []byte("Hello world!\n")); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if session.ExitCode() != 0 {
		t.Fatalf("invalid exit code returned: %d", session.ExitCode())
	}
	_ = session.Close()
}

func (c *conformanceTestSuite) runningInteractiveShellShouldWork(t *testing.T) {
	t.Parallel()
	logger := getLogger(t)
	backend, err := c.backendFactory(logger)
	if err != nil {
		t.Fatal(err)
	}

	user := NewTestUser("test")
	user.RandomPassword()
	srv := NewTestServer(NewTestAuthenticationHandler(
		newHandler(backend),
		user,
	), logger)
	srv.Start()
	defer srv.Stop(10 * time.Second)

	client := NewTestClient(srv.GetListen(), srv.GetHostKey(), user, logger)
	connection, err := client.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = connection.Close()
	}()
	session := connection.MustSession()
	if err := session.SetEnv("foo", "bar"); err != nil {
		t.Error(err)
		return
	}
	if err := session.RequestPTY("xterm", 80, 25); err != nil {
		t.Error(err)
		return
	}
	if err := session.Shell(); err != nil {
		t.Error(err)
		return
	}
	if c.testShellInteraction(t, session) {
		return
	}
	if err := session.Wait(); err != nil {
		t.Error(err)
		return
	}
	if session.ExitCode() != 0 {
		t.Errorf("invalid exit code returned: %d", session.ExitCode())
		return
	}
	_ = session.Close()
}

func (c *conformanceTestSuite) testShellInteraction(t *testing.T, session TestClientSession) bool {
	session.ReadRemaining()
	if !shellCommand(t, session, "tput cols", "80\r\n") {
		return true
	}
	if !shellCommand(t, session, "tput lines", "25\r\n") {
		return true
	}
	if err := session.Window(120, 25); err != nil {
		t.Error(err)
		return true
	}
	// Give Kubernetes time to realize the window change. Docker doesn't need this.
	time.Sleep(time.Second)
	// Read any output after the window change
	session.ReadRemaining()
	if !shellCommand(t, session, "tput cols", "120\r\n") {
		return true
	}
	if !shellCommand(t, session, "tput lines", "25\r\n") {
		return true
	}
	if !shellCommand(t, session, "echo \"Hello world!\"", "Hello world!\r\n") {
		return true
	}
	if !shellCommand(t, session, "exit", "") {
		return true
	}
	return false
}

func (c *conformanceTestSuite) reportingExitCodeShouldWork(t *testing.T) {
	t.Parallel()
	logger := getLogger(t)
	backend, err := c.backendFactory(logger)
	if err != nil {
		t.Fatal(err)
	}

	user := NewTestUser("test")
	user.RandomPassword()
	srv := NewTestServer(NewTestAuthenticationHandler(
		newHandler(backend),
		user,
	), logger)
	srv.Start()
	defer srv.Stop(10 * time.Second)

	client := NewTestClient(srv.GetListen(), srv.GetHostKey(), user, logger)
	connection, err := client.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = connection.Close()
	}()
	session := connection.MustSession()
	if err := session.Exec("exit 42"); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if session.ExitCode() != 42 {
		t.Fatalf("invalid exit code returned: %d", session.ExitCode())
	}
	_ = session.Close()
}

func (c *conformanceTestSuite) sendingSignalsShouldWork(t *testing.T) {
	t.Parallel()
	logger := getLogger(t)
	backend, err := c.backendFactory(logger)
	if err != nil {
		t.Fatal(err)
	}

	user := NewTestUser("test")
	user.RandomPassword()
	srv := NewTestServer(NewTestAuthenticationHandler(
		newHandler(backend),
		user,
	), logger)
	srv.Start()
	defer srv.Stop(10 * time.Second)

	client := NewTestClient(srv.GetListen(), srv.GetHostKey(), user, logger)
	connection, err := client.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = connection.Close()
	}()
	session := connection.MustSession()
	if err := session.Exec("sleep infinity & PID=$!; trap \"kill $PID\" USR1; wait; echo \"USR1 received\""); err != nil {
		t.Fatal(err)
	}
	if err := session.Signal("USR1"); err != nil {
		t.Fatal(err)
	}
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.WaitForStdout(timeout, []byte("USR1 received\n")); err != nil {
		t.Fatal(err)
	}
	if err := session.Wait(); err != nil {
		t.Fatal(err)
	}
	if session.ExitCode() != 0 {
		t.Fatalf("invalid exit code returned: %d", session.ExitCode())
	}
	_ = session.Close()
}

func shellCommand(t *testing.T, session TestClientSession, command string, expectResponse string) bool {
	if err := session.Type([]byte(fmt.Sprintf("%s\n", command))); err != nil {
		t.Error(err)
		return false
	}
	timeout, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := session.WaitForStdout(
		timeout,
		[]byte(expectResponse),
	); err != nil {
		t.Error(err)
		return false
	}
	if !strings.Contains("exit", command) {
		session.ReadRemaining()
	}
	return true
}

func newHandler(backend NetworkConnectionHandler) *handler {
	return &handler{backend: backend}
}

type handler struct {
	AbstractHandler

	backend NetworkConnectionHandler
}

func (h *handler) OnNetworkConnection(_ net.TCPAddr, _ string) (NetworkConnectionHandler, error) {
	return h.backend, nil
}
