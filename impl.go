package sshserver

import (
	"context"
	"fmt"
	"net"

	"github.com/containerssh/log"
	"golang.org/x/crypto/ssh"
)

type server struct {
	listener          net.Listener
	cfg               Config
	logger            log.Logger
	ctx               context.Context
	shutdownContext   context.Context
	cancelFunc        context.CancelFunc
	handler           Handler
}

func (s *server) Run() error {
	s.logger.Infof("starting SSH server on %s", s.cfg.Listen)
	netListener, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("failed to start SSH server on %s (%v)", s.cfg.Listen, err)
	}
	defer func() {
		if err := netListener.Close(); err != nil {
			s.logger.Warningf("failed to close listen socket (%v)", err)
		}
	}()
	if err := s.handler.OnReady(); err != nil {
		return err
	}

	for {
		tcpConn, err := netListener.Accept()
		if err != nil {
			// Assume listen socket closed
			break
		}
		networkConnection, err := s.handler.OnNetworkConnection(tcpConn.RemoteAddr())
		if err != nil {
			s.logger.Infoe(err)
			_ = tcpConn.Close()
			continue
		}

		sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, sshConfig)
		if err != nil {
			networkConnection.OnDisconnect()
			_ = tcpConn.Close()
			continue
		}
		go func() {
			_ = sshConn.Wait()
			networkConnection.OnDisconnect()
		}()
		select {

		}
	}
}

func (s *server) Shutdown(shutdownContext context.Context) {
	if s.listener == nil {
		return
	}
	s.handler.OnShutdown(shutdownContext)
	s.cancelFunc()
	s.shutdownContext = shutdownContext
}

