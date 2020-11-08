package sshserver_test

import (
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/containerssh/log/standard"
	"github.com/stretchr/testify/assert"

	"github.com/containerssh/sshserver"
)

type rejectHandler struct {
}

func (r *rejectHandler) OnReady() error {
	return fmt.Errorf("rejected")
}

func (r *rejectHandler) OnShutdown(_ context.Context) {
}

func (r *rejectHandler) OnNetworkConnection(_ net.Addr) (sshserver.NetworkConnection, error) {
	return nil, fmt.Errorf("not implemented")
}

func TestReadyRejection(t *testing.T) {
	config := sshserver.DefaultConfig()
	if err := config.GenerateHostKey(); err != nil {
		assert.Fail(t, "failed to generate host key", err)
		return
	}
	logger := standard.New()
	handler := &rejectHandler{}

	server, err := sshserver.New(config, handler, logger)
	if err != nil {
		assert.Fail(t, "failed to create server", err)
		return
	}
	err = server.Run()
	if err == nil {
		assert.Fail(t, "server.Run() did not result in an error")
	} else {
		assert.Equal(t, "rejected", err.Error())
	}
}
