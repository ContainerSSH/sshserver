package sshserver

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/rand"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// NewTestUser creates a user that can be used with NewTestHandler and NewTestClient.
func NewTestUser(username string) *TestUser {
	return &TestUser{
		username: username,
	}
}

// TestUser is a container for a username, a password and public keys
type TestUser struct {
	username       string
	password       string
	privateKeys    []*rsa.PrivateKey
	authorizedKeys []string
}

// Username returns the username of this user.
func (u *TestUser) Username() string {
	return u.username
}

// Password returns the current password for this user.
func (u *TestUser) Password() string {
	return u.password
}

// SetPassword sets a specific password for this user.
func (u *TestUser) SetPassword(password string) {
	u.password = password
}

// RandomPassword generates a random password for this user.
func (u *TestUser) RandomPassword() {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	length := 16
	runes := []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
		"abcdefghijklmnopqrstuvwxyz" +
		"0123456789!%$#-_=+")
	var passwordBuilder strings.Builder
	for i := 0; i < length; i++ {
		passwordBuilder.WriteRune(runes[random.Intn(len(runes))])
	}
	u.password = passwordBuilder.String()
}

// GenerateKey generates a public and private key pair that can be used to authenticate with this user.
func (u *TestUser) GenerateKey() (privateKeyPEM string, publicKeyAuthorizedKeys string) {
	random := rand.New(rand.NewSource(time.Now().UnixNano()))
	privateKey, err := rsa.GenerateKey(random, 2048)
	if err != nil {
		panic(err)
	}

	privPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	var privateKeyPEMBuffer bytes.Buffer
	if err := pem.Encode(&privateKeyPEMBuffer, privPEM); err != nil {
		panic(err)
	}
	privateKeyPEM = privateKeyPEMBuffer.String()

	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	publicKeyAuthorizedKeys = string(ssh.MarshalAuthorizedKey(pub))

	u.privateKeys = append(u.privateKeys, privateKey)
	u.authorizedKeys = append(u.authorizedKeys, privateKeyPEM)

	return privateKeyPEM, publicKeyAuthorizedKeys
}

// GetAuthorizedKeys returns a slice of the authorized keys of this user.
func (u *TestUser) GetAuthorizedKeys() []string {
	return u.authorizedKeys
}

func (u *TestUser) getAuthMethods() []ssh.AuthMethod {
	var result []ssh.AuthMethod
	if u.password != "" {
		result = append(result, ssh.Password(u.password))
	}
	var pubKeys []ssh.Signer
	for _, privateKey := range u.privateKeys {
		signer, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			panic(err)
		}
		pubKeys = append(pubKeys, signer)
	}
	result = append(result, ssh.PublicKeys(pubKeys...))
	return result
}
