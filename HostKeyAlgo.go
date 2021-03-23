package sshserver

import (
	"fmt"
)

var supportedHostKeyAlgos = []stringer{
	HostKeyAlgoSSHRSACertv01, HostKeyAlgoSSHDSSCertv01, HostKeyAlgoECDSASHA2NISTp256Certv01,
	HostKeyAlgoECDSASHA2NISTp384Certv01, HostKeyAlgoECDSASHA2NISTp521Certv01, HostKeyAlgoSSHED25519Certv01,
	HostKeyAlgoSSHRSA, HostKeyAlgoSSHDSS, HostKeyAlgoSSHED25519,
}

// HostKeyAlgo are supported host key algorithms.
type HostKeyAlgo string

// HostKeyAlgo are supported host key algorithms.
const (
	HostKeyAlgoSSHRSACertv01            HostKeyAlgo = "ssh-rsa-cert-v01@openssh.com"
	HostKeyAlgoSSHDSSCertv01            HostKeyAlgo = "ssh-dss-cert-v01@openssh.com"
	HostKeyAlgoECDSASHA2NISTp256Certv01 HostKeyAlgo = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	HostKeyAlgoECDSASHA2NISTp384Certv01 HostKeyAlgo = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	HostKeyAlgoECDSASHA2NISTp521Certv01 HostKeyAlgo = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
	HostKeyAlgoSSHED25519Certv01        HostKeyAlgo = "ssh-ed25519-cert-v01@openssh.com"
	HostKeyAlgoSSHRSA                   HostKeyAlgo = "ssh-rsa"
	HostKeyAlgoSSHDSS                   HostKeyAlgo = "ssh-dss"
	HostKeyAlgoSSHED25519               HostKeyAlgo = "ssh-ed25519"
)

// String creates a string representation.
func (h HostKeyAlgo) String() string {
	return string(h)
}

// Validate checks if a given host key algorithm is valid.
func (h HostKeyAlgo) Validate() error {
	if h == "" {
		return fmt.Errorf("empty host key algorithm")
	}
	for _, algo := range supportedHostKeyAlgos {
		if algo == h {
			return nil
		}
	}
	return fmt.Errorf("unsupported host key algorithm: %s", h)
}
