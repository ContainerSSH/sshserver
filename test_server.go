package sshserver

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/containerssh/log"
	"github.com/containerssh/service"
	"github.com/containerssh/structutils"
)

// TestServer describes
type TestServer interface {
	// GetHostKey returns the hosts private key in PEM format. This can be used to extract the public key.
	GetHostKey() string
	// Start starts the server in the background.
	Start()
	// Stop stops the server running in the background.
	Stop(timeout time.Duration)
}

// NewTestServer is a simplified API to start and stop a test server. The test server always listens on 127.0.0.1:2222
func NewTestServer(handler Handler) TestServer {
	logger, err := log.New(
		log.Config{
			Level:  log.LevelDebug,
			Format: log.FormatText,
		},
		"ssh",
		os.Stdout,
	)
	if err != nil {
		panic(err)
	}
	config := Config{}
	structutils.Defaults(&config)
	config.Listen = "127.0.0.1:2222"
	if err := config.GenerateHostKey(); err != nil {
		panic(err)
	}
	svc, err := New(config, handler, logger)
	if err != nil {
		panic(err)
	}
	lifecycle := service.NewLifecycle(svc)
	started := make(chan struct{})
	lifecycle.OnRunning(
		func(s service.Service, l service.Lifecycle) {
			started <- struct{}{}
		})

	return &testServer{
		config:    config,
		lifecycle: lifecycle,
		started:   started,
	}
}

type testServer struct {
	config    Config
	lifecycle service.Lifecycle
	started   chan struct{}
}

func (t *testServer) GetHostKey() string {
	return t.config.HostKeys[0]
}

var testServerLock = &sync.Mutex{}

func (t *testServer) Start() {
	if t.lifecycle.State() != service.StateStopped {
		panic(fmt.Errorf("server already running"))
	}
	testServerLock.Lock()
	go func() {
		_ = t.lifecycle.Run()
	}()
	<-t.started
}

func (t *testServer) Stop(timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	t.lifecycle.Stop(ctx)
	testServerLock.Unlock()
}
