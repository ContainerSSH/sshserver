package sshserver

import (
	"fmt"

	"golang.org/x/crypto/ssh"
)

// Cipher is the SSH cipher
type Cipher string

// Cipher is the SSH cipher
const (
	CipherChaCha20Poly1305 Cipher = "chacha20-poly1305@openssh.com"
	CipherAES256GCM        Cipher = "aes256-gcm@openssh.com"
	CipherAES128GCM        Cipher = "aes128-gcm@openssh.com"
	CipherAES256CTE        Cipher = "aes256-ctr"
	CipherAES192CTR        Cipher = "aes192-ctr"
	CipherAES128CTR        Cipher = "aes128-ctr"
	CipherAES128CBC        Cipher = "aes128-cbc"
	CipherArcFour256       Cipher = "arcfour256"
	CipherArcFour128       Cipher = "arcfour128"
	CipherArcFour          Cipher = "arcfour"
	CipherTripleDESCBCID   Cipher = "tripledescbcID"
)

// Kex are the SSH key exchange algorithms
type Kex string

const (
	KexCurve25519SHA256 Kex = "curve25519-sha256@libssh.org"
	KexECDHSHA2NISTp521 Kex = "ecdh-sha2-nistp521"
	KexECDHSHA2Nistp384 Kex = "ecdh-sha2-nistp384"
	KexECDHSHA2Nistp256 Kex = "ecdh-sha2-nistp256"
	KexDHGroup14SHA1    Kex = "diffie-hellman-group14-sha1"
	KexDHGroup1SHA1     Kex = "diffie-hellman-group1-sha1"
)

// MAC are the SSH mac algorithms.
type MAC string

// MAC are the SSH mac algorithms.
const (
	MACHMACSHA2256ETM MAC = "hmac-sha2-256-etm@openssh.com"
	MACHMACSHA2256    MAC = "hmac-sha2-256"
	MACHMACSHA1       MAC = "hmac-sha1"
	MACHMACSHA196     MAC = "hmac-sha1-96"
)

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

// Config is the base configuration structure of the SSH server.
type Config struct {
	// Listen is the listen address for the SSH server
	Listen string
	// ServerVersion is the version sent to the client.
	ServerVersion string `json:"serverVersion" yaml:"serverVersion" default:"ContainerSSH"`
	// Ciphers are the ciphers offered to the client.
	Ciphers []Cipher `json:"ciphers" yaml:"ciphers" default:"[\"chacha20-poly1305@openssh.com\",\"aes256-gcm@openssh.com\",\"aes128-gcm@openssh.com\",\"aes256-ctr\",\"aes192-ctr\",\"aes128-ctr\"]" comment:"Cipher suites to use"`
	// KexAlgorithms are the key exchange algorithms offered to the client.
	KexAlgorithms []Kex `json:"kex" yaml:"kex" default:"[\"curve25519-sha256@libssh.org\",\"ecdh-sha2-nistp521\",\"ecdh-sha2-nistp384\",\"ecdh-sha2-nistp256\"]" comment:"Key exchange algorithms to use"`
	// MACs are the MAC algorithms offered to the client.
	MACs []MAC `json:"macs" yaml:"macs" default:"[\"hmac-sha2-256-etm@openssh.com\",\"hmac-sha2-256\",\"hmac-sha1\",\"hmac-sha1-96\"]" comment:"MAC algorithms to use"`
	// Banner is the banner sent to the client on connecting.
	Banner string `json:"banner" yaml:"banner" comment:"Host banner to show after the username"`
	// HostKeys are the host keys either in PEM format, or filenames to load.
	HostKeys []string `json:"hostkeys" yaml:"hostkeys" comment:"Host keys in PEM format or files to load PEM host keys from."`
}

func (cfg Config) ProcessAndValidate() error {
	validators := []func() error{
		cfg.validateCiphers,
		cfg.validateKexAlgorithms,
		cfg.validateMACs,
	}

	for _, validator := range validators {
		err := validator()
		if err != nil {
			return err
		}
	}
	return nil
}

var supportedCiphers = []Cipher{
	CipherChaCha20Poly1305, CipherAES256GCM, CipherAES128GCM, CipherAES256CTE, CipherAES192CTR, CipherAES128CTR,
	CipherAES128CBC, CipherArcFour256, CipherArcFour128, CipherArcFour, CipherTripleDESCBCID,
}
var supportedKexAlgos = []Kex{
	KexCurve25519SHA256, KexECDHSHA2Nistp256, KexECDHSHA2Nistp384, KexECDHSHA2NISTp521,
	KexDHGroup1SHA1, KexDHGroup14SHA1,
}
var supportedHostKeyAlgos = []HostKeyAlgo{
	HostKeyAlgoSSHRSACertv01, HostKeyAlgoSSHDSSCertv01, HostKeyAlgoECDSASHA2NISTp256Certv01,
	HostKeyAlgoECDSASHA2NISTp384Certv01, HostKeyAlgoECDSASHA2NISTp521Certv01, HostKeyAlgoSSHED25519Certv01,
	HostKeyAlgoSSHRSA, HostKeyAlgoSSHDSS, HostKeyAlgoSSHED25519,
}
var supportedMACs = []MAC{
	MACHMACSHA2256ETM, MACHMACSHA2256, MACHMACSHA196, MACHMACSHA1,
}

func (cfg Config) findUnsupported(name string, requestedList interface{}, supportedList interface{}) error {
	for _, requestedItem := range requestedList.([]string) {
		found := false
		for _, supportedItem := range supportedList.([]string) {
			if supportedItem == requestedItem {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("ssh: unsupported %s %s for server", name, requestedItem)
		}
	}
	return nil
}

func (cfg Config) validateCiphers() error {
	if len(cfg.Ciphers) == 0 {
		return nil
	}
	return cfg.findUnsupported("cipher", cfg.Ciphers, supportedCiphers)
}

func (cfg Config) validateKexAlgorithms() error {
	if len(cfg.KexAlgorithms) == 0 {
		return nil
	}
	return cfg.findUnsupported("key exchange algorithm", cfg.KexAlgorithms, supportedKexAlgos)
}

func (cfg Config) validateMACs() error {
	if len(cfg.MACs) == 0 {
		return nil
	}
	return cfg.findUnsupported("MAC algorithm", cfg.MACs, supportedMACs)
}

func (cfg Config) validateHostKeys(hostKeys []ssh.Signer) error {
	if len(hostKeys) == 0 {
		return fmt.Errorf("no host keys supplied")
	}
	for index, hostKey := range hostKeys {
		if hostKey == nil {
			return fmt.Errorf("host key %d is nil (probably not loaded correctly)", index)
		}
		foundHostKeyAlgo := false
		for _, hostKeyAlgo := range supportedHostKeyAlgos {
			if hostKey.PublicKey().Type() == string(hostKeyAlgo) {
				foundHostKeyAlgo = true
			}
		}
		if !foundHostKeyAlgo {
			return fmt.Errorf("unknown host key format (%s)", hostKey.PublicKey().Type())
		}
	}
	return nil
}
