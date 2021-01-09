package sshserver_test

import (
	"context"
	"testing"
	"time"

	"github.com/containerssh/sshserver"
)

func TestProperShutdown(t *testing.T) {
	user := sshserver.NewTestUser("foo")
	user.RandomPassword()
	testServer := sshserver.NewTestServer(
		sshserver.NewTestAuthenticationHandler(
			sshserver.NewTestHandler(),
			user,
		),
	)
	testServer.Start()

	testClient := sshserver.NewTestClient(testServer, user)
	connection := testClient.MustConnect()
	session := connection.MustSession()
	session.MustRequestPTY("xterm", 80, 25)
	session.MustShell()
	_ = session.WaitForStdout(context.Background(), []byte("> "))

	finished := make(chan struct{})
	go func() {
		testServer.Stop(60 * time.Second)
		finished <- struct{}{}
	}()
	go func() {
		_ = session.Wait()
		if err := connection.Close(); err != nil {
			t.Errorf("%v", err)
		}
	}()
	select {
	case <-time.After(30 * time.Second):
		t.Fail()
	case <-finished:
	}
}
