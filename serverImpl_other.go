// +build plan9

package v2

import (
	"syscall"
)

func (s *serverImpl) socketControl(network, address string, conn syscall.RawConn) error {
	return conn.Control(func(descriptor uintptr) {
	})
}
