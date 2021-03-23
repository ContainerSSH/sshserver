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
	ServerVersion ServerVersion `json:"serverVersion" yaml:"serverVersion" default:"SSH-2.0-ContainerSSH"`
	// Ciphers are the ciphers offered to the client.
	Ciphers CipherList `json:"ciphers" yaml:"ciphers" default:"[\"chacha20-poly1305@openssh.com\",\"aes256-gcm@openssh.com\",\"aes128-gcm@openssh.com\",\"aes256-ctr\",\"aes192-ctr\",\"aes128-ctr\"]" comment:"Cipher suites to use"`
	// KexAlgorithms are the key exchange algorithms offered to the client.
	KexAlgorithms KexList `json:"kex" yaml:"kex" default:"[\"curve25519-sha256@libssh.org\",\"ecdh-sha2-nistp521\",\"ecdh-sha2-nistp384\",\"ecdh-sha2-nistp256\"]" comment:"Key exchange algorithms to use"`
	// MACs are the MAC algorithms offered to the client.
	MACs MACList `json:"macs" yaml:"macs" default:"[\"hmac-sha2-256-etm@openssh.com\",\"hmac-sha2-256\"]" comment:"MAC algorithms to use"`
	// Banner is the banner sent to the client on connecting.
	Banner string `json:"banner" yaml:"banner" comment:"Host banner to show after the username" default:""`
	// HostKeys are the host keys either in PEM format, or filenames to load.
	HostKeys []string `json:"hostkeys" yaml:"hostkeys" comment:"Host keys in PEM format or files to load PEM host keys from."`
}

// DefaultConfig returns the default configuration.
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

		if err := HostKeyAlgo(keyType).Validate(); err != nil {
			return nil, fmt.Errorf("unsupported host key algorithm %s on host key %d", keyType, index)
		}
		hostKeys = append(hostKeys, private)
	}
	return hostKeys, nil
}

// Validate validates the configuration and returns an error if invalid.
func (cfg Config) Validate() error {
	if err := cfg.ServerVersion.Validate(); err != nil {
		return fmt.Errorf("invalid server version (%w)", err)
	}
	if err := cfg.Ciphers.Validate(); err != nil {
		return fmt.Errorf("invalid cipher list (%w)", err)
	}
	if err := cfg.KexAlgorithms.Validate(); err != nil {
		return fmt.Errorf("invalid key exchange algorithms list (%w)", err)
	}
	if err := cfg.MACs.Validate(); err != nil {
		return fmt.Errorf("invalid MAc list (%w)", err)
	}
	return nil
}
