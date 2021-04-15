package v2

import (
	"fmt"
)

var supportedHostKeyAlgos = []stringer{
	KeyAlgoSSHRSACertv01, KeyAlgoSSHDSSCertv01, KeyAlgoECDSASHA2NISTp256Certv01,
	KeyAlgoECDSASHA2NISTp384Certv01, KeyAlgoECDSASHA2NISTp521Certv01, KeyAlgoSSHED25519Certv01,
	KeyAlgoSSHRSA, KeyAlgoSSHDSS, KeyAlgoSSHED25519,
}

// KeyAlgo are supported key algorithms.
type KeyAlgo string

// KeyAlgo are supported key algorithms.
const (
	KeyAlgoSSHRSACertv01            KeyAlgo = "ssh-rsa-cert-v01@openssh.com"
	KeyAlgoSSHDSSCertv01            KeyAlgo = "ssh-dss-cert-v01@openssh.com"
	KeyAlgoECDSASHA2NISTp256Certv01 KeyAlgo = "ecdsa-sha2-nistp256-cert-v01@openssh.com"
	KeyAlgoECDSASHA2NISTp384Certv01 KeyAlgo = "ecdsa-sha2-nistp384-cert-v01@openssh.com"
	KeyAlgoECDSASHA2NISTp521Certv01 KeyAlgo = "ecdsa-sha2-nistp521-cert-v01@openssh.com"
	KeyAlgoSSHED25519Certv01        KeyAlgo = "ssh-ed25519-cert-v01@openssh.com"
	KeyAlgoSSHRSA                   KeyAlgo = "ssh-rsa"
	KeyAlgoSSHDSS                   KeyAlgo = "ssh-dss"
	KeyAlgoSSHED25519               KeyAlgo = "ssh-ed25519"
)

// String creates a string representation.
func (h KeyAlgo) String() string {
	return string(h)
}

// Validate checks if a given key algorithm is valid.
func (h KeyAlgo) Validate() error {
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
