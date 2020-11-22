# 0.9.3: Upgraded this library to match the new service library (November 22, 2020)

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

# 0.9.2: Added request and channel IDs (November 15, 2020)

**This release adds unique global request IDs, channel IDs and channel request IDs.**

In this change we are adding an uint64 parameter to all handler methods that deal with requests and channels. IDs are unique within their scope: global request IDs are unique among all global requests within the connection, channel IDs are guaranteed to be unique among all channel IDs within the conection, and channel request IDs are guaranteed to be unique within the channel. These IDs are also guaranteed to be monotonic, but they are not guaranteed to be continuous.

Furthermore, the `onExit` methods in the `SessionChannelHandler` interface now take the alias type `sshserver.ExitStatus` instead of `uint32` to provide better documentation.

The affected method changes are listed below.

## Changes to the `SSHConnectionHandler` interface

- `OnUnsupportedGlobalRequest(requestID uint64, ...)`: added `requestID`
- `OnUnsupportedChannel(channelID uint64, ...)`: added `channelID`
- `OnSessionChannel(channelID uint64, ...) (...)`: added `channelID`

## Changes to the `SessionChannelHandler` interface

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

# 0.9.1: Better OnNetworkConnection API (November 15, 2020)

**This release changes the API of the `OnNetworkConnection()` method of the `Handler` interface.**

This preview release changes the API of the `OnNetworkConnection()` method to a) ensure easier implementation of IP address logging, and b) introduce a global unique identifier for connections. This is done such that connections can be identified across multiple log formats.

The API now looks like this:

```go
type Handler interface {
    //...
    OnNetworkConnection(ip net.TCPAddr, connectionID []byte) (NetworkConnectionHandler, error)
}
```

## Changes to the `ip` parameter

Previously, the `ip` parameter was of the type `net.Addr` and is now changed to `*net.TCPAddr`. This was the default because the Go SSH library supports SSH connections over non-IP transports such as Unix sockets. However, the only use case for this scenario seems to be for writing tests so ContainerSSH does not support it. Therefore, we are changing the API to make it easier to extract the IP address and connecting port of the client.

## Adding the `connectionID` parameter

We are also adding the `connectionID` parameter. This parameter was previously generated in the [auditlog](https://github.com/containerssh/auditlog) library for audit logging purposes only. This change is done so that multiple libraries (e.g. auth, auditlog, etc) can use the same connection ID to track the connection across these systems.

---

# 0.9.0: Initial version (November 8, 2020)

This is the initial version of the SSH server library.

## Using this library

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

## Implementing a handler

The handler interface consists of multiple parts:

- The `Handler` is the main handler for the application providing several hooks for events. On new connections the `OnNetworkConnection` method is called, which must return a `NetworkConnectionHandler`
- The `NetworkConnectionHandler` is a handler for network connections before the SSH handshake is complete. It is called to perform authentication and return an `SSHConnectionHandler` when the authentication is successful.
- The `SSHConnectionHandler` is responsible for handling an individual SSH connection. Most importantly, it is responsible for providing a `SessionChannelHandler` when a new session channel is requested by the client.
- The `SessionChannelHandler` is responsible for an individual session channel (single program execution). It provides several hooks for setting up and running the program. Once the program execution is complete the channel is closed. You must, however, keep handling requests (e.g. window size change) during program execution.

A sample implementation can be found in the [test code](server_impl.go) at the bottom of the file.