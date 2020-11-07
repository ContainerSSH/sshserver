package sshserver

import (
	"context"
	"sync"

	"github.com/containerssh/log"
)

// New creates a new SSH server ready to be run. It may return an error if the configuration is invalid.
//goland:noinspection GoUnusedExportedFunction
func New(cfg Config, handler Handler, logger log.Logger) (Server, error) {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &server{
		cfg:             cfg,
		handler:         handler,
		logger:          logger,
		ctx:             ctx,
		cancelFunc:      cancelFunc,
		wg:              &sync.WaitGroup{},
		lock:            &sync.Mutex{},
		shutdownContext: nil,
		listenSocket:    nil,
	}, nil
}
