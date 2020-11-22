package sshserver

import (
	"sync"

	"github.com/containerssh/log"
)

// New creates a new SSH server ready to be run. It may return an error if the configuration is invalid.
func New(cfg Config, handler Handler, logger log.Logger) (Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &server{
		cfg:          cfg,
		handler:      handler,
		logger:       logger,
		wg:           &sync.WaitGroup{},
		lock:         &sync.Mutex{},
		listenSocket: nil,
	}, nil
}
