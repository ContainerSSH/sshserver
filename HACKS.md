# Hacks

This file is intended to keep track of the hacks in the SSH server library.

## OnHandshakeSuccess handler

We call the `OnHandshakeSuccess` handler from the authentication methods. We do this so the `OnHandshakeSuccess` handler can perform longer initialization methods without sending the auth success message to the client.

We are doing this because immediately after the client receives the auth successful message it will start sending requests which may time out.

We can do this because we know that the Go SSH library doesn't support chained authentication. (e.g. password + keyboard-interactive).

**Remove:** When Go SSH supports multiple chained authentication methods.
