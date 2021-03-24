# Message / error codes

| Code | Explanation |
|------|-------------|
| `SSH_ALREADY_RUNNING` | The SSH server is already running and has been started again. This is a bug, please report it. |
| `SSH_AUTH_FAILED` | The user has provided invalid credentials. |
| `SSH_AUTH_SUCCESSFUL` | The user has provided valid credentials and is now authenticated. |
| `SSH_AUTH_UNAVAILABLE` | The user has requested an authentication method that is currently unavailable. |
| `SSH_AVAILABLE` | The SSH service is now online and ready for service. |
| `SSH_BACKEND_REJECTED_HANDSHAKE` | The backend has rejected the connecting user after successful authentication. |
| `SSH_CHANNEL_REQUEST` | The user has send a new channel-specific request. |
| `SSH_CHANNEL_REQUEST_FAILED` | ContainerSSH couldn't fulfil the channel-specific request. |
| `SSH_CHANNEL_REQUEST_SUCCESSFUL` | ContainerSSH has successfully processed the channel-specific request. |
| `SSH_CONNECTED` | A user has connected over SSH. |
| `SSH_DECODE_FAILED` | ContainerSSH failed to decode something from the user. This is either a bug in ContainerSSH or in the connecting client. |
| `SSH_DISCONNECTED` | An SSH connection has been severed. |
| `SSH_EXIT` | ContainerSSH is sending the exit code of the program to the user. |
| `SSH_EXIT_CODE_FAILED` | ContainerSSH failed to obtain and send the exit code of the program to the user. |
| `SSH_EXIT_SIGNAL` | ContainerSSH is sending the exit signal from an abnormally exited program to the user. |
| `SSH_HANDSHAKE_FAILED` | The connecting party failed to establish a secure SSH connection. This is most likely due to invalid credentials or a backend error. |
| `SSH_HANDSHAKE_SUCCESSFUL` | The user has provided valid credentials and has now established an SSH connection. |
| `SSH_LISTEN_CLOSE_FAILED` | ContainerSSH failed to close the listen socket. |
| `SSH_NEW_CHANNEL` | A user has established a new SSH channel. (Not connection!) |
| `SSH_NEW_CHANNEL_REJECTED` | The user has requested a new channel to be opened, but was rejected. |
| `SSH_REPLY_SEND_FAILED` | ContainerSSH couldn't send the reply to a request to the user. This is usually the case if the user suddenly disconnects. |
| `SSH_SOCKET_REUSE_FAILED` | ContainerSSH failed to set the socket to reuse. This may cause ContainerSSH to fail on a restart. |
| `SSH_START_FAILED` | ContainerSSH failed to start the SSH service. This is usually because of invalid configuration. |
| `SSH_UNSUPPORTED_CHANNEL_TYPE` | The user requested a channel type that ContainerSSH doesn't support (e.g. TCP/IP forwarding). |
| `SSH_UNSUPPORTED_GLOBAL_REQUEST` | The users client has send a global request ContainerSSH does not support. This is nothing to worry about. |

