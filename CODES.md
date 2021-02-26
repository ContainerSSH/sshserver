# Error/message codes

| Code | Explanation |
|------|-------------|
| `SSH_ALREADY_RUNNING` | The SSH service is already running. This is a bug. |
| `SSH_START_FAILED` | Failed to start the SSH service. See the error message for details. |
| `SSH_LISTEN_CLOSE_FAILED` | ContainerSSH could not close the listen socket on shutdown. |
| `SSH_AVAILABLE` | This message informs you that the SSH service is now available at the specified location. |
| `SSH_AUTH_UNAVAILABLE` | The attempted authentication method was not available. |
| `SSH_AUTH_FAILED` | Authentication failed. Multiple of these messages may be issued for a single connection. |
| `SSH_AUTH_SUCCESSFUL` | Authentication attempt successful. |