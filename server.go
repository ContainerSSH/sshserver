package sshserver

import (
	"context"
)

// Server is the main server for running a server
type Server interface {
	// Run runs the server synchronously. This function returns when the server has stopped.
	Run() error

	// Shutdown signals the server to not accept any more connections and shut down. When shutdownContext
	// expires the server aborts active connections and shuts down the server.
	// The method waits for the server to shut down.
	Shutdown(shutdownContext context.Context)
}
