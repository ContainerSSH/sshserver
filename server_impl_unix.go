// +build linux darwin

package sshserver

import (
	"syscall"
)

func (s *server) socketControl(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
		err := syscall.SetsockoptInt(
			int(descriptor),
			syscall.SOL_SOCKET,
			syscall.SO_REUSEADDR,
			1,
		)
		if err != nil {
			s.logger.Warningf("failed to set SO_REUSEADDR. Server may fail on restart")
		}
	})
}
