// +build windows

package sshserver

import (
	"syscall"
)

func (s *server) socketControl(_, _ string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		err := syscall.SetsockoptInt(
			syscall.Handle(descriptor),
			syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR,
			1,
		)
		if err != nil {
			s.logger.Warningf("failed to set SO_REUSEADDR. Server may fail on restart")
		}
	})
}
