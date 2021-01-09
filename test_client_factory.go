package sshserver

import (
	"os"

	"github.com/containerssh/log"
	"golang.org/x/crypto/ssh"
)

// NewTestClient creates a new TestClient instance with the specified parameters
//
// - hostPrivateKey is the PEM-encoded private host key. The public key and fingerprint are automatically extracted.
// - server is the host and IP pair of the server.
// - username is the username.
// - password is the password used for authentication.
func NewTestClient(
	server TestServer,
	user *TestUser,
) TestClient {
	private, err := ssh.ParsePrivateKey([]byte(server.GetHostKey()))
	if err != nil {
		panic(err)
	}

	logger, err := log.New(
		log.Config{
			Level:  log.LevelDebug,
			Format: log.FormatText,
		},
		"test-client",
		os.Stdout,
	)
	if err != nil {
		panic(err)
	}

	return &testClient{
		logger:  logger,
		server:  server.GetListen(),
		hostKey: private.PublicKey().Marshal(),
		user:    user,
	}
}
