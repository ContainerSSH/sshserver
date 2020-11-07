package sshserver

// Cipher is the SSH cipher
type Cipher string

const (
	CipherChaCha20Poly1305 Cipher = "chacha20-poly1305@openssh.com"
	CipherAes256Gcm        Cipher = "aes256-gcm@openssh.com"
	CipherAes128Gcm        Cipher = "aes128-gcm@openssh.com"
	CipherAes256Ctr        Cipher = "aes256-ctr"
	CipherAes192Ctr        Cipher = "aes192-ctr"
	CipherAes128Ctr        Cipher = "aes128-ctr"
)

// Kex are the SSH key exchange algorithms
type Kex string

const (
	KexCurve25519Sha256 Kex = "curve25519-sha256@libssh.org"
	KexEcdhSha2Nistp521 Kex = "ecdh-sha2-nistp521"
	KexEcdhSha2Nistp284 Kex = "ecdh-sha2-nistp384"
	KexEcdhSha2Nistp256 Kex = "ecdh-sha2-nistp256"
)

// Mac are the SSH mac algorithms
type Mac string

const (
	MacHmacSha2256Etm Mac = "hmac-sha2-256-etm@openssh.com"
	MacHmacSha2256    Mac = "hmac-sha2-256"
	MacHmacSha1       Mac = "hmac-sha1"
	MacHmacSha196     Mac = "hmac-sha1-96"
)

type Config struct {
	Listen        string
	Ciphers       []string `json:"ciphers" yaml:"ciphers" default:"[\"chacha20-poly1305@openssh.com\",\"aes256-gcm@openssh.com\",\"aes128-gcm@openssh.com\",\"aes256-ctr\",\"aes192-ctr\",\"aes128-ctr\"]" comment:"Cipher suites to use"`
	KexAlgorithms []string `json:"kex" yaml:"kex" default:"[\"curve25519-sha256@libssh.org\",\"ecdh-sha2-nistp521\",\"ecdh-sha2-nistp384\",\"ecdh-sha2-nistp256\"]" comment:"Key exchange algorithms to use"`
	Macs          []string `json:"macs" yaml:"macs" default:"[\"hmac-sha2-256-etm@openssh.com\",\"hmac-sha2-256\",\"hmac-sha1\",\"hmac-sha1-96\"]" comment:"MAC algorithms to use"`
	HostKeys      []string `json:"hostkeys" yaml:"hostkeys" comment:"Host key files to use. Files must be in PEM format"`
	Banner        string   `json:"banner" yaml:"banner" comment:"Host banner to show after the username"`
}
