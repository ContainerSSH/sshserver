package sshserver

import (
	"golang.org/x/crypto/ssh"
)

type notImplementedRejection struct {
}

func (n *notImplementedRejection) Error() string {
	return "not implemented"
}

func (n *notImplementedRejection) Message() string {
	return "not implemented"
}

func (n *notImplementedRejection) Reason() ssh.RejectionReason {
	return ssh.UnknownChannelType
}
