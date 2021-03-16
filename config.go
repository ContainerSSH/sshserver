package sshserver

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/containerssh/structutils"
)

// Config is the base configuration structure of the SSH server.
type Config struct {
	// Listen is the listen address for the SSH server
	Listen string `json:"listen" yaml:"listen" default:"0.0.0.0:2222"`
	// ServerVersion is the version sent to the client.
	//               Must be in the format of "SSH-protoversion-softwareversion SPACE comments".
	//               See https://tools.ietf.org/html/rfc4253#page-4 section 4.2. Protocol Version Exchange
	//               The trailing CR and LF characters should NOT be added to this string.
	ServerVersion string `json:"serverVersion" yaml:"serverVersion" default:"SSH-2.0-ContainerSSH"`
	// Ciphers are the ciphers offered to the client.
	Ciphers []Cipher `json:"ciphers" yaml:"ciphers" default:"[\"chacha20-poly1305@openssh.com\",\"aes256-gcm@openssh.com\",\"aes128-gcm@openssh.com\",\"aes256-ctr\",\"aes192-ctr\",\"aes128-ctr\"]" comment:"Cipher suites to use"`
	// KexAlgorithms are the key exchange algorithms offered to the client.
	KexAlgorithms []Kex `json:"kex" yaml:"kex" default:"[\"curve25519-sha256@libssh.org\",\"ecdh-sha2-nistp521\",\"ecdh-sha2-nistp384\",\"ecdh-sha2-nistp256\"]" comment:"Key exchange algorithms to use"`
	// MACs are the MAC algorithms offered to the client.
	MACs []MAC `json:"macs" yaml:"macs" default:"[\"hmac-sha2-256-etm@openssh.com\",\"hmac-sha2-256\"]" comment:"MAC algorithms to use"`
	// Banner is the banner sent to the client on connecting.
	Banner string `json:"banner" yaml:"banner" comment:"Host banner to show after the username" default:""`
	// HostKeys are the host keys either in PEM format, or filenames to load.
	HostKeys []string `json:"hostkeys" yaml:"hostkeys" comment:"Host keys in PEM format or files to load PEM host keys from."`
}

func DefaultConfig() Config {
	cfg := Config{}
	structutils.Defaults(&cfg)
	return cfg
}

// GenerateHostKey generates a random host key and adds it to Config
func (cfg *Config) GenerateHostKey() error {
	reader := rand.Reader
	bitSize := 4096
	key, err := rsa.GenerateKey(reader, bitSize)
	if err != nil {
		return err
	}
	var privateKey = &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}
	var hostKeyBuffer bytes.Buffer
	err = pem.Encode(&hostKeyBuffer, privateKey)
	if err != nil {
		return err
	}

	cfg.HostKeys = append(cfg.HostKeys, hostKeyBuffer.String())
	return nil
}

//region Getters

func (cfg *Config) getKex() []string {
	kex := make([]string, len(cfg.KexAlgorithms))
	for i, k := range cfg.KexAlgorithms {
		kex[i] = k.String()
	}
	return kex
}

func (cfg *Config) getMACs() []string {
	macs := make([]string, len(cfg.MACs))
	for i, v := range cfg.MACs {
		macs[i] = v.String()
	}
	return macs
}

func (cfg *Config) getCiphers() []string {
	ciphers := make([]string, len(cfg.Ciphers))
	for i, v := range cfg.Ciphers {
		ciphers[i] = v.String()
	}
	return ciphers
}

//endregion

//region Unmarshal

func (cfg *Config) LoadHostKeys() ([]ssh.Signer, error) {
	var hostKeys []ssh.Signer
	for index, hostKey := range cfg.HostKeys {
		if strings.TrimSpace(hostKey)[:5] != "-----" {
			//Load file
			fh, err := os.Open(hostKey)
			if err != nil {
				return nil, fmt.Errorf("failed to load host key %s (%w)", hostKey, err)
			}
			hostKeyData, err := ioutil.ReadAll(fh)
			if err != nil {
				_ = fh.Close()
				return nil, fmt.Errorf("failed to load host key %s (%w)", hostKey, err)
			}
			if err = fh.Close(); err != nil {
				return nil, fmt.Errorf("failed to close host key file %s (%w)", hostKey, err)
			}
			hostKey = string(hostKeyData)
		}
		private, err := ssh.ParsePrivateKey([]byte(hostKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key (%w)", err)
		}
		keyType := private.PublicKey().Type()

		found := false
		for _, supportedHostKeyAlgo := range supportedHostKeyAlgos {
			if keyType == supportedHostKeyAlgo.String() {
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("unsupported host key algorithm %s on host key %d", keyType, index)
		}
		hostKeys = append(hostKeys, private)
	}
	return hostKeys, nil
}

//endregion

//region Constants

type stringer interface {
	String() string
}

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

// String creates a string representation.
func (c Cipher) String() string {
	return string(c)
}

// Kex are the SSH key exchange algorithms
type Kex string

// Kex are the SSH key exchange algorithms
const (
	KexCurve25519SHA256 Kex = "curve25519-sha256@libssh.org"
	KexECDHSHA2NISTp521 Kex = "ecdh-sha2-nistp521"
	KexECDHSHA2Nistp384 Kex = "ecdh-sha2-nistp384"
	KexECDHSHA2Nistp256 Kex = "ecdh-sha2-nistp256"
	KexDHGroup14SHA1    Kex = "diffie-hellman-group14-sha1"
	KexDHGroup1SHA1     Kex = "diffie-hellman-group1-sha1"
)

// String creates a string representation.
func (k Kex) String() string {
	return string(k)
}

// MAC are the SSH mac algorithms.
type MAC string

// MAC are the SSH mac algorithms.
const (
	MACHMACSHA2256ETM MAC = "hmac-sha2-256-etm@openssh.com"
	MACHMACSHA2256    MAC = "hmac-sha2-256"
	MACHMACSHA1       MAC = "hmac-sha1"
	MACHMACSHA196     MAC = "hmac-sha1-96"
)

// String creates a string representation.
func (m MAC) String() string {
	return string(m)
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

//endregion

//region Validation

// Validate validates the configuration and returns an error if invalid.
func (cfg Config) Validate() error {
	validators := []func() error{
		cfg.validateServerVersion,
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

var supportedCiphers = []stringer{
	CipherChaCha20Poly1305, CipherAES256GCM, CipherAES128GCM, CipherAES256CTE, CipherAES192CTR, CipherAES128CTR,
	CipherAES128CBC, CipherArcFour256, CipherArcFour128, CipherArcFour, CipherTripleDESCBCID,
}
var supportedKexAlgos = []stringer{
	KexCurve25519SHA256, KexECDHSHA2Nistp256, KexECDHSHA2Nistp384, KexECDHSHA2NISTp521,
	KexDHGroup1SHA1, KexDHGroup14SHA1,
}
var supportedHostKeyAlgos = []stringer{
	HostKeyAlgoSSHRSACertv01, HostKeyAlgoSSHDSSCertv01, HostKeyAlgoECDSASHA2NISTp256Certv01,
	HostKeyAlgoECDSASHA2NISTp384Certv01, HostKeyAlgoECDSASHA2NISTp521Certv01, HostKeyAlgoSSHED25519Certv01,
	HostKeyAlgoSSHRSA, HostKeyAlgoSSHDSS, HostKeyAlgoSSHED25519,
}
var supportedMACs = []stringer{
	MACHMACSHA2256ETM, MACHMACSHA2256, MACHMACSHA196, MACHMACSHA1,
}

func (cfg Config) findUnsupported(name string, requestedList []stringer, supportedList []stringer) error {
	for _, requestedItem := range requestedList {
		found := false
		for _, supportedItem := range supportedList {
			if supportedItem.String() == requestedItem.String() {
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

var serverVersionRegexp = regexp.MustCompile(`^SSH-2.0-[a-zA-Z0-9]+(| [a-zA-Z0-9- _.]+)$`)

func (cfg Config) validateServerVersion() error {
	if !serverVersionRegexp.MatchString(cfg.ServerVersion) {
		return fmt.Errorf("invalid server version string (%s), see https://tools.ietf.org/html/rfc4253#page-4 section 4.2. for details", cfg.ServerVersion)
	}
	return nil
}

func (cfg Config) validateCiphers() error {
	if len(cfg.Ciphers) == 0 {
		return nil
	}

	cipherList := make([]stringer, len(cfg.Ciphers))
	for i, cipher := range cfg.Ciphers {
		cipherList[i] = cipher
	}

	return cfg.findUnsupported("cipher", cipherList, supportedCiphers)
}

func (cfg Config) validateKexAlgorithms() error {
	if len(cfg.KexAlgorithms) == 0 {
		return nil
	}

	kexList := make([]stringer, len(cfg.KexAlgorithms))
	for i, cipher := range cfg.KexAlgorithms {
		kexList[i] = cipher
	}

	return cfg.findUnsupported("key exchange algorithm", kexList, supportedKexAlgos)
}

func (cfg Config) validateMACs() error {
	if len(cfg.MACs) == 0 {
		return nil
	}

	macList := make([]stringer, len(cfg.MACs))
	for i, cipher := range cfg.MACs {
		macList[i] = cipher
	}

	return cfg.findUnsupported("MAC algorithm", macList, supportedMACs)
}

//endregion
