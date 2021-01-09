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

var testServerLock = &sync.Mutex{}
var nextPort = 2222

// TestServer describes
type TestServer interface {
	// GetHostKey returns the hosts private key in PEM format. This can be used to extract the public key.
	GetHostKey() string
	// Start starts the server in the background.
	Start()
	// Stop stops the server running in the background.
	Stop(timeout time.Duration)

	// GetListen returns the listen IP and port
	GetListen() string
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

	testServerLock.Lock()
	config.Listen = fmt.Sprintf("127.0.0.1:%d", nextPort)
	nextPort++
	testServerLock.Unlock()
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

func (t *testServer) GetListen() string {
	return t.config.Listen
}

func (t *testServer) GetHostKey() string {
	return t.config.HostKeys[0]
}

func (t *testServer) Start() {
	if t.lifecycle.State() != service.StateStopped {
		panic(fmt.Errorf("server already running"))
	}
	go func() {
		_ = t.lifecycle.Run()
	}()
	<-t.started
}

func (t *testServer) Stop(timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	t.lifecycle.Stop(ctx)
}
