package sshserver

import (
	"context"
	"net"
)

// NewTestAuthenticationHandler creates a new backend that authenticates a user based on the users variable and passes
// all further calls to the backend.
func NewTestAuthenticationHandler(
	backend Handler,
	users ...*TestUser,
) Handler {
	return &testAuthenticationHandler{
		users:   users,
		backend: backend,
	}
}

// testAuthenticationHandler is a handler that authenticates and passes authentication to the configured backend.
type testAuthenticationHandler struct {
	users   []*TestUser
	backend Handler
}

func (t *testAuthenticationHandler) OnReady() error {
	return t.backend.OnReady()
}

func (t *testAuthenticationHandler) OnShutdown(ctx context.Context) {
	t.backend.OnShutdown(ctx)
}

func (t *testAuthenticationHandler) OnNetworkConnection(client net.TCPAddr, connectionID string) (NetworkConnectionHandler, error) {
	backend, err := t.backend.OnNetworkConnection(client, connectionID)
	if err != nil {
		return nil, err
	}

	return &testAuthenticationNetworkHandler{
		rootHandler: t,
		backend:     backend,
	}, nil
}

type testAuthenticationNetworkHandler struct {
	rootHandler *testAuthenticationHandler
	backend     NetworkConnectionHandler
}

func (t *testAuthenticationNetworkHandler) OnDisconnect() {
	t.backend.OnDisconnect()
}

func (t *testAuthenticationNetworkHandler) OnShutdown(shutdownContext context.Context) {
	t.backend.OnShutdown(shutdownContext)
}

func (t *testAuthenticationNetworkHandler) OnAuthPassword(username string, password []byte) (response AuthResponse, reason error) {
	for _, user := range t.rootHandler.users {
		if user.username == username && user.password == string(password) {
			return AuthResponseSuccess, nil
		}
	}
	return AuthResponseFailure, ErrAuthenticationFailed
}

func (t *testAuthenticationNetworkHandler) OnAuthPubKey(username string, pubKey string) (response AuthResponse, reason error) {
	for _, user := range t.rootHandler.users {
		if user.username == username {
			for _, authorizedKey := range user.authorizedKeys {
				if pubKey == authorizedKey {
					return AuthResponseSuccess, nil
				}
			}
		}
	}
	return AuthResponseFailure, ErrAuthenticationFailed
}

func (t *testAuthenticationNetworkHandler) OnHandshakeFailed(err error) {
	t.backend.OnHandshakeFailed(err)
}

func (t *testAuthenticationNetworkHandler) OnHandshakeSuccess(username string) (
	connection SSHConnectionHandler,
	failureReason error,
) {
	return t.backend.OnHandshakeSuccess(username)
}
