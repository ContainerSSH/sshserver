package sshserver

import (
	"context"

	"github.com/containerssh/log"
)

func New(
	cfg Config,
	handler Handler,
	logger log.Logger,
) Server {
	ctx, cancelFunc := context.WithCancel(context.Background())
	return &server{
		cfg: cfg,
		handler: handler,
		logger: logger,
		ctx: ctx,
		cancelFunc: cancelFunc,
	}
}
