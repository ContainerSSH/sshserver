package sshserver

import (
	"context"
	"io"
	"net"

	"golang.org/x/crypto/ssh"
)

// Handler is the basic handler for SSH connections. It contains several methods to handle startup and operations of the
//         server
type Handler interface {
	// OnReady is called when the server is ready to receive connections. It has an opportunity to return an error to
	//         abort the startup.
	OnReady() error

	// OnShutdown is called when a shutdown of the SSH server is desired. The shutdownContext is passed as a deadline
	//            for the shutdown, after which the server should abort all running connections and return as fast as
	//            possible.
	OnShutdown(shutdownContext context.Context)

	// OnNetworkConnection is called when a new network connection is opened. It must either return a
	// NetworkConnectionHandler object or an error. In case of an error the network connection is closed.
	//
	// The ip parameter provides the IP address of the connecting user. The connectionID parameter provides an opaque
	// binary identifier for the connection that can be used to track the connection across multiple subsystems.
	OnNetworkConnection(client net.TCPAddr, connectionID []byte) (NetworkConnectionHandler, error)
}

// AuthResponse indicates the various response states for the authentication process.
type AuthResponse uint8

const (
	// AuthResponseSuccess indicates that the authentication was successful.
	AuthResponseSuccess AuthResponse = 1

	// AuthResponseFailure indicates that the authentication failed for invalid credentials.
	AuthResponseFailure AuthResponse = 2

	// AuthResponseUnavailable indicates that the authentication could not be performed because a backend system failed
	//                         to respond.
	AuthResponseUnavailable AuthResponse = 3
)

// NetworkConnectionHandler is an object that is used to represent the underlying network connection and the SSH handshake.
type NetworkConnectionHandler interface {
	// OnAuthPassword is called when a user attempts a password authentication. The implementation must always supply
	//                AuthResponse and may supply error as a reason description.
	OnAuthPassword(username string, password []byte) (response AuthResponse, reason error)

	// OnAuthPassword is called when a user attempts a pubkey authentication. The implementation must always supply
	//                AuthResponse and may supply error as a reason description.
	OnAuthPubKey(username string, pubKey []byte) (response AuthResponse, reason error)

	// OnHandshakeFailed is called when the SSH handshake failed. This method is also called after an authentication
	//                   failure. After this method is the connection will be closed and the OnDisconnect method will be
	//                   called.
	OnHandshakeFailed(reason error)

	// OnHandshakeSuccess is called when the SSH handshake was successful. It returns connection to process
	//                    requests, or failureReason to indicate that a backend error has happened. In this case, the
	//                    connection will be closed and OnDisconnect will be called.
	OnHandshakeSuccess() (connection SSHConnectionHandler, failureReason error)

	// OnDisconnect is called when the network connection is closed.
	OnDisconnect()
}

// ChannelRejection is an error type that also contains a Message and a Reason
type ChannelRejection interface {
	error

	// Message contains a message intended for the user.
	Message() string
	// Reason contains the SSH-specific reason for the rejection.
	Reason() ssh.RejectionReason
}

// SSHConnectionHandler represents an established SSH connection that is ready to receive requests.
type SSHConnectionHandler interface {
	// OnUnsupportedGlobalRequest captures all global SSH requests and gives the implementation an opportunity to log
	//                            the request.
	OnUnsupportedGlobalRequest(requestType string, payload []byte)

	// OnUnsupportedChannel is called when a new channel is requested of an unsupported type. This gives the implementer
	//                      the ability to log unsupported channel requests.
	OnUnsupportedChannel(channelType string, extraData []byte)

	// OnSessionChannel is called when a channel of the session type is requested. The implementer must either return
	//                  the channel result if the channel was successful, or failureReason to state why the channel
	//                  should be rejected.
	OnSessionChannel(extraData []byte) (channel SessionChannelHandler, failureReason ChannelRejection)
}

// SessionChannelHandler is a channel of the "session" type used for interactive and non-interactive sessions
type SessionChannelHandler interface {
	// OnUnsupportedChannelRequest captures channel requests of unsupported types.
	OnUnsupportedChannelRequest(
		requestType string,
		payload []byte,
	)

	// OnFailedDecodeChannelRequest is called when a supported channel request was received, but the payload could not
	//                              be decoded.
	OnFailedDecodeChannelRequest(
		requestType string,
		payload []byte,
		reason error,
	)

	// OnEnvRequest is called when the client requests an environment variable to be set. The implementation can return
	//              an error to reject the request.
	OnEnvRequest(
		name string,
		value string,
	) error

	// OnExecRequest is called when the client request a program to be executed. The implementation can return an error
	//               to reject the request.
	//
	// program is the name of the program to be executed.
	// stdin is a reader for the shell or program to read the stdin.
	// stdout is a writer for the shell or program standard output.
	// stderr is a writer for the shell or program standard error.
	// onExit is a callback to send the exit status back to the client.
	OnExecRequest(
		program string,
		stdin io.Reader,
		stdout io.Writer,
		stderr io.Writer,
		onExit func(exitStatus uint32),
	) error

	// OnPtyRequest is called when the client requests an interactive terminal to be allocated. The implementation can
	//              return an error to reject the request.
	//
	// term is the terminal name. This is usually set in the TERM environment variable.
	// columns is the number of columns in the terminal.
	// rows is the number of rows in the terminal.
	// width is the width of the terminal in pixels.
	// height is the height of a terminal in pixels.
	// modelist are the encoded terminal modes the client desires. See RFC4254 section 8 and RFC8160 for details.
	OnPtyRequest(
		term string,
		columns uint32,
		rows uint32,
		width uint32,
		height uint32,
		modeList []byte,
	) error

	// OnShell is called when the client requests a shell to be started. The implementation can return an error to
	//         reject the request. The implementation should send the IO handling into background. It should also
	//         respect the shutdown context on the Handler.
	//
	// stdin is a reader for the shell or program to read the stdin.
	// stdout is a writer for the shell or program standard output.
	// stderr is a writer for the shell or program standard error.
	// onExit is a callback to send the exit status back to the client.
	OnShell(
		stdin io.Reader,
		stdout io.Writer,
		stderr io.Writer,
		onExit func(exitStatus uint32),
	) error

	// OnSignal is called when the client requests a signal to be sent to the running process. The implementation can
	//          return an error to reject the request.
	OnSignal(signal string) error

	// OnSubsystem is called when the client calls a well-known subsystem (e.g. sftp). The implementation can return an
	//             error to reject the request. The implementation should send the IO handling into background. It
	//             should also respect the shutdown context on the Handler.
	//
	// stdin is a reader for the shell or program to read the stdin.
	// stdout is a writer for the shell or program standard output.
	// stderr is a writer for the shell or program standard error.
	// onExit is a callback to send the exit status back to the client.
	OnSubsystem(
		subsystem string,
		stdin io.Reader,
		stdout io.Writer,
		stderr io.Writer,
		onExit func(exitStatus uint32),
	) error

	// OnWindow is called when the client requests requests the window size to be changed. The implementation can
	//              return an error to reject the request.
	//
	// columns is the number of columns in the terminal.
	// rows is the number of rows in the terminal.
	// width is the width of the terminal in pixels.
	// height is the height of a terminal in pixels.
	OnWindow(
		columns uint32,
		rows uint32,
		width uint32,
		height uint32,
	) error
}
