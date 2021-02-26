# Changelog

## 0.9.18: Moving to new logger

This releaser cleans up logging and moves to the new logger 0.9.11.

## 0.9.17: Fixing shutdown double-call

This release fixes a bug where the OnShutdown function on the handler was called twice.

## 0.9.16: Keyboard-interactive authentication

This release adds support for keyboard-interactive authentication.

## 0.9.15: Testing framework

This release adds a wide range of testing utilities that can be used to construct an SSH server or client for testing purposes.

## 0.9.14: Fixed incorrect request types

In the previous version the SSH server would listen for several incorrect request types, for example PTY, signals, and subsystems. These are now fixed.

## 0.9.13: Fixed race condition on channel requests

The previous version of this library would handle channel requests in parallel goroutines. This would sometimes lead to shell/exec/subsystem requests being processed before PTY requests. This release changes that and requests are now always processed in order.

## 0.9.12: Moving the OnHandshakeSuccessful handler to authentication

This change moves the call to OnHandshakeSuccessful before sending the "auth success" message to the client.

This is required because we noticed that clients would immediately start sending requests (e.g. PTY requests) to the server while the container backend is still initializing. If the container initialization takes too long the PTY request would be considered failed by the client resulting in the error message "PTY allocation request failed on channel 0". By delaying sending the authentication response to the client we can make sure the container backend has ample time to start up the container.

## 0.9.11: Exec request bug

This release fixes a bug where Exec requests would be rejected due to faulty refactoring in the previous release.

Currently, there is no test for this scenario, but later on, a full test suite for supported SSH requests is desired.

## 0.9.10: Bugfixing request decoding

In the previous versions of this library the fields in the structures related to SSH requests (e.g. env) were not exported. This caused the ssh unmarshal to fail, but this was not tested previously. We have now changed the fields to be exported and sending requests has now been added to the test scope. More test cases are desirable in future.

## 0.9.9: Configuration structure now accepts strings instead of ssh.Signer
          
This change replaces the host keys configuration parameter ([]ssh.Signer) with a slice of strings. This is done to preserve the file-based host keys when a configuration structure needs to be saved later.

## 0.9.8: Changing the pubKey authenticator to use the authorized key format

In this release we are changing the `OnAuthPubKey` method of the `NetworkConnectionHandler` interface to receive a `string` instead of a `[]byte` for the pubkey. The SSH server implementation now passes the SSH key in the [OpenSSH authorized key format](https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#~/.ssh/authorized_keys) to make it easier for implementers to match the key.

## 0.9.7: Changing `connectionID`

This release changes the `connectionID` parameter to a string. This better conveys that it is a printable string and can be safely used in filenames, etc.

## 0.9.6: OnHandshakeSuccess takes username

With `0.9.6` we are introducing the `user` parameter to the `OnHandshakeSuccess()` method. This is done in preparation to supporting SSH connections without authentication.

## 0.9.5: Bugfixing the OnReady handler

In 0.9.3 we introduced a bug in the OnReady handler that caused the listen socket to stay open even if the OnReady handler exited with an error. This resulted in an "address already in use" error on Linux.

## 0.9.4: Bugfixing the shutdown hander

This release contains a bugfix from 0.9.3 where the shutdown handler would not be properly called after the refactor. This release properly calls the shutdown handler.

## 0.9.3: Upgraded this library to match the new service library (November 22, 2020)

Previously, the SSH server could be started and stopped directly using the `Run()` and `Shutdown()` methods. This change integrates the SSH server with the new [service library](https://github.com/containerssh/service) that makes it easier to manage multiple services in a single daemon. As a side effect, the SSH server can now only be started using the `Lifecycle` object:

```go
// Create the server. See the description below for parameters.
server, err := sshserver.New(
    cfg,
    handler,
    logger,
)
if err != nil {
    // Handle configuration errors
    log.Fatalf("%v", err)
}
lifecycle := service.NewLifecycle(server)

defer func() {
    // The Run method will run the server and return when the server is shut down.
    // We are running this in a goroutine so the shutdown below can proceed after a minute.
    if err := lifecycle.Run(); err != nil {
        // Handle errors while running the server
    }
}()

time.Sleep(60 * time.Second)

// Shut down the server. Pass a context to indicate how long the server should wait
// for existing connections to finish. This function will return when the server
// has stopped. 
lifecycle.Stop(
    context.WithTimeout(
        context.Background(),
        30 * time.Second,
    ),
)
```

This gives you the option to register hooks for the various lifecycle events. For more details see the [service library](https://github.com/containerssh/service).

---

## 0.9.2: Added request and channel IDs (November 15, 2020)

**This release adds unique global request IDs, channel IDs and channel request IDs.**

In this change we are adding an uint64 parameter to all handler methods that deal with requests and channels. IDs are unique within their scope: global request IDs are unique among all global requests within the connection, channel IDs are guaranteed to be unique among all channel IDs within the conection, and channel request IDs are guaranteed to be unique within the channel. These IDs are also guaranteed to be monotonic, but they are not guaranteed to be continuous.

Furthermore, the `onExit` methods in the `SessionChannelHandler` interface now take the alias type `sshserver.ExitStatus` instead of `uint32` to provide better documentation.

The affected method changes are listed below.

### Changes to the `SSHConnectionHandler` interface

- `OnUnsupportedGlobalRequest(requestID uint64, ...)`: added `requestID`
- `OnUnsupportedChannel(channelID uint64, ...)`: added `channelID`
- `OnSessionChannel(channelID uint64, ...) (...)`: added `channelID`

### Changes to the `SessionChannelHandler` interface

- `OnUnsupportedChannelRequest(requestID uint64, ...)`: added `requestID`
- `OnFailedDecodeChannelRequest(requestID uint64, ...)`: added `requestID`
- `OnEnvRequest(requestID uint64, ...)`: added `requestID`
- `OnPtyRequest(requestID uint64, ...)`: added `requestID`
- `OnExecRequest(requestID uint64, ..., onExit func(exitStatus ExitStatus))`: added `requestID`, changed `onExit`
- `OnShell(requestID uint64, ..., onExit func(exitStatus ExitStatus))`: added `requestID`, changed `onExit`
- `OnSubsystem(requestID uint64, ..., onExit func(exitStatus ExitStatus))`: added `requestID`, changed `onExit`
- `OnSignal(requestID uint64, ...)`: added `requestID`
- `OnWindow(requestID uint64, ...)`: added `requestID`

---

## 0.9.1: Better OnNetworkConnection API (November 15, 2020)

**This release changes the API of the `OnNetworkConnection()` method of the `Handler` interface.**

This preview release changes the API of the `OnNetworkConnection()` method to a) ensure easier implementation of IP address logging, and b) introduce a global unique identifier for connections. This is done such that connections can be identified across multiple log formats.

The API now looks like this:

```go
type Handler interface {
    //...
    OnNetworkConnection(ip net.TCPAddr, connectionID []byte) (NetworkConnectionHandler, error)
}
```

### Changes to the `ip` parameter

Previously, the `ip` parameter was of the type `net.Addr` and is now changed to `*net.TCPAddr`. This was the default because the Go SSH library supports SSH connections over non-IP transports such as Unix sockets. However, the only use case for this scenario seems to be for writing tests so ContainerSSH does not support it. Therefore, we are changing the API to make it easier to extract the IP address and connecting port of the client.

### Adding the `connectionID` parameter

We are also adding the `connectionID` parameter. This parameter was previously generated in the [auditlog](https://github.com/containerssh/auditlog) library for audit logging purposes only. This change is done so that multiple libraries (e.g. auth, auditlog, etc) can use the same connection ID to track the connection across these systems.

---

## 0.9.0: Initial version (November 8, 2020)

This is the initial version of the SSH server library.

### Using this library

This library provides a friendlier way to handle SSH requests than with the built-in SSH library. As a primary entry
point you will need to create and run the SSH server:

```go
// Create the server. See the description below for parameters.
server, err := sshserver.New(
    cfg,
    handler,
    logger,
)
if err != nil {
    // Handle configuration errors
    log.Fatalf("%v", err)
}

defer func() {
    // The Run method will run the server and return when the server is shut down.
    // We are running this in a goroutine so the shutdown below can proceed after a minute.
    if err := server.Run(); err != nil {
        // Handle errors while running the server
    }
}()

time.Sleep(60 * time.Second)

// Shut down the server. Pass a context to indicate how long the server should wait
// for existing connections to finish. This function will return when the server
// has stopped. 
server.Shutdown(
    context.WithTimeout(
        context.Background(),
        30 * time.Second,
    ),
)
```

The `cfg` variable will be a `Config` structure as described in [config.go](config.go).

The `handler` variable must be an implementation of the [`Handler` interface described in handler.go](handler.go).

The `logger` variable needs to be an instance of the `Logger` interface from [github.com/containerssh/log](https://github.com/containerssh/log).

### Implementing a handler

The handler interface consists of multiple parts:

- The `Handler` is the main handler for the application providing several hooks for events. On new connections the `OnNetworkConnection` method is called, which must return a `NetworkConnectionHandler`
- The `NetworkConnectionHandler` is a handler for network connections before the SSH handshake is complete. It is called to perform authentication and return an `SSHConnectionHandler` when the authentication is successful.
- The `SSHConnectionHandler` is responsible for handling an individual SSH connection. Most importantly, it is responsible for providing a `SessionChannelHandler` when a new session channel is requested by the client.
- The `SessionChannelHandler` is responsible for an individual session channel (single program execution). It provides several hooks for setting up and running the program. Once the program execution is complete the channel is closed. You must, however, keep handling requests (e.g. window size change) during program execution.

A sample implementation can be found in the [test code](server_impl.go) at the bottom of the file.