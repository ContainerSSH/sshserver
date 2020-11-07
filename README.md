[![ContainerSSH - Launch Containers on Demand](https://containerssh.github.io/images/logo-for-embedding.svg)](https://containerssh.github.io/)

<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">ContainerSSH SSH Server Library</h1>

[![Go Report Card](https://goreportcard.com/badge/github.com/containerssh/sshserver?style=for-the-badge)](https://goreportcard.com/report/github.com/containerssh/sshserver)
[![LGTM Alerts](https://img.shields.io/lgtm/alerts/github/ContainerSSH/sshserver?style=for-the-badge)](https://lgtm.com/projects/g/ContainerSSH/sshserver/)

This library provides an overlay for the built-in go SSH server library that makes it easier to handle.

<p align="center"><strong>Note: This is a developer documentation.</strong><br />The user documentation for ContainerSSH is located at <a href="https://containerssh.github.io">containerssh.github.io</a>.</p>

## Using this library

This library provides a friendlier way to handle SSH requests than with the built-in SSH library. As a primary entry
point you will need to create and run the SSH server:

```go
// Create the server. See description below for parameters.
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
// for existing connections to finish. This function will return when the server has stopped. 
server.Shutdown(
    context.WithTimeout(
        context.Background(),
        30 * time.Second,
    ),
)
```

The `cfg` variable will be a `Config` structure as described in [config.go](config.go).

The `handler` must be an implementation of the [`Handler` interface described in handler.go](handler.go).

 The `logger` variable needs to be an instance of a `Logger` from [github.com/containerssh/log](https://github.com/containerssh/log).