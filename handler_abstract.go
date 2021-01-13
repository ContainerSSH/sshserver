package sshserver

import (
	"context"
	"fmt"
	"net"

	"golang.org/x/crypto/ssh"
)

// AbstractHandler is the abstract implementation of the Handler interface that can be embedded to get a partial
// implementation.
type AbstractHandler struct {
}

// OnReady is called when the server is ready to receive connections. It has an opportunity to return an error to
//         abort the startup.
func (a *AbstractHandler) OnReady() error {
	return nil
}

// OnShutdown is called when a shutdown of the SSH server is desired. The shutdownContext is passed as a deadline
//            for the shutdown, after which the server should abort all running connections and return as fast as
//            possible.
func (a *AbstractHandler) OnShutdown(_ context.Context) {
}

// OnNetworkConnection is called when a new network connection is opened. It must either return a
// NetworkConnectionHandler object or an error. In case of an error the network connection is closed.
//
// The ip parameter provides the IP address of the connecting user. The connectionID parameter provides an opaque
// binary identifier for the connection that can be used to track the connection across multiple subsystems.
func (a *AbstractHandler) OnNetworkConnection(_ net.TCPAddr, _ string) (NetworkConnectionHandler, error) {
	return nil, fmt.Errorf("not implemented")
}

// AbstractNetworkConnectionHandler is an empty implementation for the NetworkConnectionHandler interface.
type AbstractNetworkConnectionHandler struct {
}

// OnAuthPassword is called when a user attempts a password authentication. The implementation must always supply
//                AuthResponse and may supply error as a reason description.
func (a *AbstractNetworkConnectionHandler) OnAuthPassword(_ string, _ []byte) (response AuthResponse, reason error) {
	return AuthResponseUnavailable, nil
}

// OnAuthPassword is called when a user attempts a pubkey authentication. The implementation must always supply
//                AuthResponse and may supply error as a reason description. The pubKey parameter is an SSH key in
//               the form of "ssh-rsa KEY HERE".
func (a *AbstractNetworkConnectionHandler) OnAuthPubKey(_ string, _ string) (response AuthResponse, reason error) {
	return AuthResponseUnavailable, nil
}

// OnAuthKeyboardInteractive is a callback for interactive authentication. The implementer will be passed a callback
// function that can be used to issue challenges to the user. These challenges can, but do not have to contain
// questions.
func (a *AbstractNetworkConnectionHandler) OnAuthKeyboardInteractive(
	_ string,
	_ func(
		instruction string,
		questions KeyboardInteractiveQuestions,
	) (answers KeyboardInteractiveAnswers, err error),
) (response AuthResponse, reason error) {
	return AuthResponseUnavailable, nil
}

// OnHandshakeFailed is called when the SSH handshake failed. This method is also called after an authentication
//                   failure. After this method is the connection will be closed and the OnDisconnect method will be
//                   called.
func (a *AbstractNetworkConnectionHandler) OnHandshakeFailed(_ error) {

}

// OnHandshakeSuccess is called when the SSH handshake was successful. It returns connection to process
//                    requests, or failureReason to indicate that a backend error has happened. In this case, the
//                    connection will be closed and OnDisconnect will be called.
func (a *AbstractNetworkConnectionHandler) OnHandshakeSuccess(_ string) (
	connection SSHConnectionHandler, failureReason error,
) {
	return nil, fmt.Errorf("not implemented")
}

// OnDisconnect is called when the network connection is closed.
func (a *AbstractNetworkConnectionHandler) OnDisconnect() {
}

// OnShutdown is called when a shutdown of the SSH server is desired. The shutdownContext is passed as a deadline
//            for the shutdown, after which the server should abort all running connections and return as fast as
//            possible.
func (a *AbstractNetworkConnectionHandler) OnShutdown(_ context.Context) {}

// AbstractSSHConnectionHandler is an empty implementation of the SSHConnectionHandler providing default methods.
type AbstractSSHConnectionHandler struct {
}

// OnUnsupportedGlobalRequest captures all global SSH requests and gives the implementation an opportunity to log
//                            the request.
//
// requestID is an ID uniquely identifying the request within the scope connection. The same ID may appear within
//           a channel.
func (a *AbstractSSHConnectionHandler) OnUnsupportedGlobalRequest(_ uint64, _ string, _ []byte) {}

// OnUnsupportedChannel is called when a new channel is requested of an unsupported type. This gives the implementer
//                      the ability to log unsupported channel requests.
//
// channelID is an ID uniquely identifying the channel within the connection.
// channelType is the type of channel requested by the client. We only support the "session" channel type
// extraData contains the binary extra data submitted by the client. This is usually empty.
func (a *AbstractSSHConnectionHandler) OnUnsupportedChannel(_ uint64, _ string, _ []byte) {}

type notImplementedRejection struct {
}

func (n *notImplementedRejection) Error() string {
	return "not implemented"
}

func (n *notImplementedRejection) Message() string {
	return "not implemented"
}

func (n *notImplementedRejection) Reason() ssh.RejectionReason {
	return ssh.UnknownChannelType
}

// OnSessionChannel is called when a channel of the session type is requested. The implementer must either return
//                  the channel result if the channel was successful, or failureReason to state why the channel
//                  should be rejected.
func (a *AbstractSSHConnectionHandler) OnSessionChannel(_ uint64, _ []byte, _ SessionChannel) (
	channel SessionChannelHandler, failureReason ChannelRejection,
) {
	return nil, &notImplementedRejection{}
}

// OnShutdown is called when a shutdown of the SSH server is desired. The shutdownContext is passed as a deadline
//            for the shutdown, after which the server should abort all running connections and return as fast as
//            possible.
func (a *AbstractSSHConnectionHandler) OnShutdown(_ context.Context) {}

// AbstractSessionChannelHandler is an abstract implementation of SessionChannelHandler providing default
// implementations.
type AbstractSessionChannelHandler struct {
}

// OnShutdown is called when a shutdown of the SSH server is desired. The shutdownContext is passed as a deadline
//            for the shutdown, after which the server should abort all running connections and return as fast as
//            possible.
func (a *AbstractSessionChannelHandler) OnShutdown(_ context.Context) {}

// OnClose is called when the channel is closed.
func (a *AbstractSessionChannelHandler) OnClose() {}

// OnUnsupportedChannelRequest captures channel requests of unsupported types.
//
// requestID is an incrementing number uniquely identifying this request within the channel.
// requestType contains the SSH request type.
// payload is the binary payload.
func (a *AbstractSessionChannelHandler) OnUnsupportedChannelRequest(
	_ uint64,
	_ string,
	_ []byte,
) {
}

// OnFailedDecodeChannelRequest is called when a supported channel request was received, but the payload could not
//                              be decoded.
//
// requestID is an incrementing number uniquely identifying this request within the channel.
// requestType contains the SSH request type.
// payload is the binary payload.
// reason is the reason why the decoding failed.
func (a *AbstractSessionChannelHandler) OnFailedDecodeChannelRequest(
	_ uint64,
	_ string,
	_ []byte,
	_ error,
) {
}

// OnEnvRequest is called when the client requests an environment variable to be set. The implementation can return
//              an error to reject the request.
func (a *AbstractSessionChannelHandler) OnEnvRequest(
	_ uint64,
	_ string,
	_ string,
) error {
	return fmt.Errorf("not supported")
}

// OnPtyRequest is called when the client requests an interactive terminal to be allocated. The implementation can
//              return an error to reject the request.
//
// requestID is an incrementing number uniquely identifying this request within the channel.
// Term is the terminal Name. This is usually set in the TERM environment variable.
// Columns is the number of Columns in the terminal.
// Rows is the number of Rows in the terminal.
// Width is the Width of the terminal in pixels.
// Height is the Height of a terminal in pixels.
// ModeList are the encoded terminal modes the client desires. See RFC4254 section 8 and RFC8160 for details.
func (a *AbstractSessionChannelHandler) OnPtyRequest(
	_ uint64,
	_ string,
	_ uint32,
	_ uint32,
	_ uint32,
	_ uint32,
	_ []byte,
) error {
	return fmt.Errorf("not supported")
}

// OnExecRequest is called when the client request a program to be executed. The implementation can return an error
//               to reject the request. This method MUST NOT block beyond initializing the program.
func (a *AbstractSessionChannelHandler) OnExecRequest(
	_ uint64,
	_ string,
) error {
	return fmt.Errorf("not supported")
}

// OnShell is called when the client requests a shell to be started. The implementation can return an error to
//         reject the request. The implementation should send the IO handling into background. It should also
//         respect the shutdown context on the Handler. This method MUST NOT block beyond initializing the shell.
func (a *AbstractSessionChannelHandler) OnShell(
	_ uint64,
) error {
	return fmt.Errorf("not supported")
}

// OnSubsystem is called when the client calls a well-known Subsystem (e.g. sftp). The implementation can return an
//             error to reject the request. The implementation should send the IO handling into background. It
//             should also respect the shutdown context on the Handler. This method MUST NOT block beyond
//             initializing the subsystem.
func (a *AbstractSessionChannelHandler) OnSubsystem(
	_ uint64,
	_ string,
) error {
	return fmt.Errorf("not supported")
}

//endregion

//region Requests during program execution

// OnSignal is called when the client requests a Signal to be sent to the running process. The implementation can
//          return an error to reject the request.
func (a *AbstractSessionChannelHandler) OnSignal(
	_ uint64,
	_ string,
) error {
	return fmt.Errorf("not supported")
}

// OnWindow is called when the client requests requests the window size to be changed. This method may be called
//          after a program is started. The implementation can return an error to reject the request.
//
// requestID is an incrementing number uniquely identifying this request within the channel.
// Columns is the number of Columns in the terminal.
// Rows is the number of Rows in the terminal.
// Width is the Width of the terminal in pixels.
// Height is the Height of a terminal in pixels.
func (a *AbstractSessionChannelHandler) OnWindow(
	_ uint64,
	_ uint32,
	_ uint32,
	_ uint32,
	_ uint32,
) error {
	return fmt.Errorf("not supported")
}
