package sshserver

// A user has connected over SSH.
const MConnected = "SSH_CONNECTED"

// An SSH connection has been severed.
const MDisconnected = "SSH_DISCONNECTED"

// The connecting party failed to establish a secure SSH connection. This is most likely due to invalid credentials
// or a backend error.
const EHandshakeFailed = "SSH_HANDSHAKE_FAILED"

// The user has provided valid credentials and has now established an SSH connection.
const MHandshakeSuccessful = "SSH_HANDSHAKE_SUCCESSFUL"

// The users client has send a global request ContainerSSH does not support. This is nothing to worry about.
const EUnsupportedGlobalRequest = "SSH_UNSUPPORTED_GLOBAL_REQUEST"

// ContainerSSH couldn't send the reply to a request to the user. This is usually the case if the user suddenly
// disconnects.
const EReplyFailed = "SSH_REPLY_SEND_FAILED"

// The user requested a channel type that ContainerSSH doesn't support (e.g. TCP/IP forwarding).
const EUnsupportedChannelType = "SSH_UNSUPPORTED_CHANNEL_TYPE"

// The SSH server is already running and has been started again. This is a bug, please report it.
const EAlreadyRunning = "SSH_ALREADY_RUNNING"

// ContainerSSH failed to start the SSH service. This is usually because of invalid configuration.
const EStartFailed = "SSH_START_FAILED"

// ContainerSSH failed to close the listen socket.
const EListenCloseFailed = "SSH_LISTEN_CLOSE_FAILED"

// A user has established a new SSH channel. (Not connection!)
const MNewChannel = "SSH_NEW_CHANNEL"

// The user has requested a new channel to be opened, but was rejected.
const MNewChannelRejected = "SSH_NEW_CHANNEL_REJECTED"

// The SSH service is now online and ready for service.
const MServiceAvailable = "SSH_AVAILABLE"

// The user has requested an authentication method that is currently unavailable.
const EAuthUnavailable = "SSH_AUTH_UNAVAILABLE"

// The user has provided invalid credentials.
const EAuthFailed = "SSH_AUTH_FAILED"

// The user has provided valid credentials and is now authenticated.
const EAuthSuccessful = "SSH_AUTH_SUCCESSFUL"

// ContainerSSH failed to obtain and send the exit code of the program to the user.
const EExitCodeFailed = "SSH_EXIT_CODE_FAILED"

// ContainerSSH failed to decode something from the user. This is either a bug in ContainerSSH or in the connecting
// client.
const EDecodeFailed = "SSH_DECODE_FAILED"

// ContainerSSH is sending the exit code of the program to the user.
const MExit = "SSH_EXIT"

// ContainerSSH is sending the exit signal from an abnormally exited program to the user.
const MExitSignal = "SSH_EXIT_SIGNAL"

// The user has send a new channel-specific request.
const MChannelRequest = "SSH_CHANNEL_REQUEST"

// ContainerSSH couldn't fulfil the channel-specific request.
const MChannelRequestFailed = "SSH_CHANNEL_REQUEST_FAILED"

// ContainerSSH has successfully processed the channel-specific request.
const MChannelRequestSuccessful = "SSH_CHANNEL_REQUEST_SUCCESSFUL"

// The backend has rejected the connecting user after successful authentication.
const EBackendRejected = "SSH_BACKEND_REJECTED_HANDSHAKE"

// ContainerSSH failed to set the socket to reuse. This may cause ContainerSSH to fail on a restart.
const ESOReuseFailed = "SSH_SOCKET_REUSE_FAILED"
