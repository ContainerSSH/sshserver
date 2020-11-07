package sshserver

import (
	"context"
	"io"
	"net"
)

type Handler interface {
	// OnReady is called when the server is ready to receive connections. It has an opportunity to return an error to
	//         abort the startup.
	OnReady() error
	// OnShutdown is called when a shutdown of the SSH server is desired. The shutdownContext is passed as a deadline
	//            for the shutdown, after which the server should abort all running connections and return as fast as
	//            possible.
	OnShutdown(shutdownContext context.Context)
	// Connection is called when a new network connection is opened. It must either return a NetworkConnection object or an error.
	//            In case of an error the network connection is closed.
	OnNetworkConnection(ip net.Addr) (NetworkConnection, error)
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

// NetworkConnection is an object that is used to represent the underlying network connection and the SSH handshake.
type NetworkConnection interface {
	// OnAuthPassword is called when a user attempts a password authentication. The implementation must always supply
	//                AuthResponse and may supply error as a reason description.
	OnAuthPassword(username string, password []byte) (response AuthResponse, reason error)
	// OnAuthPassword is called when a user attempts a pubkey authentication. The implementation must always supply
	//                AuthResponse and may supply error as a reason description.
	OnAuthPubKey(username string, pubKey []byte) (response AuthResponse, reason error)
	// OnHandshakeFailed is called when the SSH handshake failed. After this method is the connection will be closed and
	//                   the OnDisconnect method will be called.
	OnHandshakeFailed(reason error)
	// OnHandshakeSuccess is called when the SSH handshake was successful. It returns connection to process
	//                    requests, or failureReason to indicate that a backend error has happened. In this case, the
	//                    connection will be closed and OnDisconnect will be called.
	OnHandshakeSuccess() (connection SSHConnection, failureReason error)
	// OnDisconnect is called when the network connection is closed.
	OnDisconnect()
}

// SSHConnection represents an established SSH connection that is ready to receive requests.
type SSHConnection interface {
	// OnUnsupportedGlobalRequest captures all global SSH requests and gives the implementation an opportunity to log
	//                            the request.
	OnUnsupportedGlobalRequest(requestType string, payload []byte)
	// OnUnsupportedChannel is called when a new channel is requested of an unsupported type. This gives the implementer
	//                      the ability to log unsupported channel requests.
	OnUnsupportedChannel(channelType string, extraData []byte)
	// OnSessionChannel is called when a channel of the session type is requested. The implementer must either return
	//                  the channel result if the channel was successful, or failureReason to state why the channel
	//                  should be rejected.
	OnSessionChannel(extraData []byte) (channel SessionChannel, failureReason error)
}

// TerminalModes contains the terminal modes the client has set. See RFC4254 section 8 and RFC8160 for details.
type TerminalModes interface {
	// GetRawModelist returns the raw SSH modelist.
	GetRawModelist() []byte

	// GetInterruptCharacter returns the interrupt character (VINTR) set by the client or nil if not set.
	GetInterruptCharacter() *uint32
	// GetQuitCharacter returns the quit character (VQUIT) set by the client or nil if not set.
	GetQuitCharacter() *uint32
	// GetEraseCharacter returns the character to erase the character to the left (VERASE), or nil if not set.
	GetEraseCharacter() *uint32
	// GetKillCurrentInputLineCharacter returns the character to kill the current input line, or nil of not set.
	GetKillCurrentInputLineCharacter() *uint32
	// GetEOFCharacter returns the end-of-file character (VEOF) set by the client or nil if not set.
	GetEOFCharater() *uint32
	// GetEOLCharacter returns the end-of-line character (VEOL) set by the client or nil if not set.
	GetEOLCharacter() *uint32
	// GetAdditionalEOLCharacter returns the additional end-of-line character (VEOL2) set by the client or nil if not set.
	GetAdditionalEOLCharacter() *uint32
	// GetPauseOutputCharacter returns the character to pause the output (VSTOP) set by the client or nil if not set.
	GetPauseOutputCharacter() *uint32
	// GetStartPausedOutputCharacter returns the character to restart the output (VSTART) set by the client or nil if
	//                               not set.
	GetStartPausedOutputCharacter() *uint32
	// GetSuspendCharacter returns the character to suspend the current program (VSUSP) set by the client or nil if not
	//                     set.
	GetSuspendCharacter() *uint32
	// GetAdditionalSuspendCharacter returns the additional character to suspend the current program (VDSUSP) set by the
	//                               client, or nil if not set.
	GetAdditionalSuspendCharacter() *uint32
	// GetReprintCharacter returns the character to reprint the current input line (VREPRINT) set by the client or nil
	//                     if not set.
	GetReprintCharacter() *uint32
	// GetEraseWordCharacter returns the character to delete the word left of the cursor (VWERASE) set by the client or
	//                       nil if not set.
	GetEraseWordCharacter() *uint32
	// GetEscapeCharacter returns the character causing the next character to be interpreted literally (VLNEXT) set by
	//                    the client, or nil if not set.
	GetEscapeCharacter() *uint32
	// GetFlushCharacter returns the character to flush the output (VFLUSH) set by the client or nil if not set.
	GetFlushCharacter() *uint32
	// GetShellSwitchCharacter returns the character to switch to a different shell layer (VSWTCH) set by the client or
	//                         nil if not set.
	GetShellSwitchCharacter() *uint32
	// GetStatusCharacter returns the character to print the status line (VSTATUS) set by the client or nil if not set.
	GetStatusCharacter() *uint32
	// GetDiscardCharacter returns the character to toggle the flushing of terminal output (VDISCARD) set by the client
	//                     or nil if not set.
	GetDiscardCharacter() *uint32
	// GetIgnoreParity returns true if the client set to ignore parity (IGNPAR), false if set to not ignore, nil if not
	//                 set.
	GetIgnoreParity() *bool
	// GetMarkParity returns true if the client set to mark parity and framing errors (PARMRK), false if set to not, and
	//               nil if not set.
	GetMarkParity() *bool
	// GetCheckParityErrors returns true if the client enabled parity error checking (INPCK), false if disabled, nil if
	//                      not set.
	GetCheckParityErrors() *bool
	// GetStrip8thBit returns true if the client set to strip the 8th bit off characters (ISTRIP), false if disabled,
	//                nil if not set.
	GetStrip8thBit() *bool
	// GetMapNLCRInput returns true if the client set to map NL into CR on input (INLCR), false if disabled, nil if not
	//                 set.
	GetMapNLCRInput() *bool
	// GetIgnoreCRInput returns true if the client set to ignore CR on input (IGNCR), false if disabled, nil if not set.
	GetIgnoreCRInput() *bool
	// GetMapCRNLInput returns true if the client set to map CR to NL on input (ICRNL), false if disabled, nil if not
	//                 set.
	GetMapCRNLInput() *bool
	// GetTranslateUpperToLower returns true if the client set to translate uppercase characters to lowercase (IUCLC),
	//                          false if disabled, nil if not set.
	GetTranslateUpperToLower() *bool
	// GetEnableOutputFlowControl returns true if the client set to enable output flow control (IXON), false if
	//                            disabled, nil if not set.
	GetEnableOutputFlowControl() *bool
	// GetAnyCharacterRestart returns if the terminal should be set to restart output after stop (IXANY), false if
	//                        disabled, nil if not set.
	GetAnyCharacterRestart() *bool
	// GetEnableInputFlowControl returns true if the client set to enable input flow control (IXOFF), false if disabled,
	//                           nil if not set.
	GetEnableInputFlowControl() *bool
	// GetRingBellOnQueueFull returns true if the client set to ring the bell if the input queue is full (IMAXBEL),
	//                        false if disabled, nil if not set.
	GetRingBellOnQueueFull() *bool
	// GetUTF8Input returns true if the client set the input to be UTF-8 (IUTF8), false if disabled, nil if not set.
	//              (RFC8160)
	GetUTF8Input() *bool
	// GetEnableSignals returns true if the client set to enable signals (ISIG), false if disabled, nil if not set.
	GetEnableSignals() *bool
	// GetCanonicalizeInput returns true if the client set to enable input line canonicalization (ICANON), false if
	//                      disabled, nil if not set.
	GetCanonicalizeInput() *bool
	// GetEnableUpperCaseCharactersByEscaping returns true if preceding a lowercase character with \ should create an
	//                                        uppercase character (XCASE), false if disabled, nil if not set.
	GetEnableUpperCaseCharactersByEscaping() *bool
	// GetEnableEcho returns true if the client set echoing input back to them (ECHO), false if disabled, nil if not
	//               set.
	GetEnableEcho() *bool
	// GetVisuallyEraseCharacters returns true if the client set to visually erase characters (ECHOE), false if
	//                            disabled, nil if not set.
	GetVisuallyEraseCharacters() *bool
	// GetKillCharacterDiscardsLine returns true if the client set for the kill character to discard the current line
	//                              (ECHOK), false if disabled, nil if not set.
	GetKillCharacterDiscardsLine() *bool
	// GetEchoNLEvenIfEchoIsOff returns true if the client set to echo NL even if echo is off (ECHONL), false if
	//                          disabled, nil if not set.
	GetEchoNLEvenIfEchoIsOff() *bool
	// GetNoFlushAfterInterrupt returns true if the client set to disable flushing after interrupt (NOFLSH), false if
	//                          disabled, nil if not set.
	GetNoFlushAfterInterrupt() *bool
	// GetStopBackgroundWriting returns true if the client set to stop background jobs that try to write to the current
	//                          terminal (TOSTOP), false if disabled, nil if not set.
	GetStopBackgroundWriting() *bool
	// GetEnableExtensions returns true to enable non-POSIX special characters (IEXTEN), false if disabled, nil if not
	//                     set.
	GetEnableExtensions() *bool
	// GetEchoControlCharacters returns true if the client set to echo control characters (ECHOCTL), false if disabled,
	//                          nil if not set.
	GetEchoControlCharacters() *bool
	// GetVisualEraseForLineKill returns true if the client set to visual erase for line kill (ECHOKE), false if
	//                           disabled, nil if not set.
	GetVisualEraseForLineKill() *bool
	// GetRetypePendingInput returns the PENDIN parameter if set, nil otherwise. Sorry, we couldn't figure out what this
	//                       is.
	GetRetypePendingInput() *uint32
	// GetOutputProcessing returns true if the client enabled output processing (OPOST), false if disabled, nil if not
	//                     set.
	GetOutputProcessing() *bool
	// GetTranslateLowerToUpper returns true if the client set to translate lower characters to upper (OLCUC), false if
	//                          disabled, nil if not set.
	GetTranslateLowerToUpper() *bool
	// GetMapNLCRNL returns true if the client set to map NL characters to CL-NL (ONLCR), false if disabled, nil if not
	//              set.
	GetMapNLCRNL() *bool
	// GetTranslateCRNL returns true if the client set to translate CR to NL (OCRNL), false if disabled, nil if not set.
	GetTranslateCRNL() *bool
	// GetTranslateNLCR returns true if the client set to translate NL to CR (ONOCR), false if disabled, nil if not set.
	GetTranslateNLCR() *bool
	// GetNLReturns returns true if the client set the newline to perform a carriage return (ONLRET), false if disabled,
	//              nil if not set.
	GetNLReturns() *bool
	// Get7BitMode returns true if the client set 7 bit mode (CS7), false if disabled, nil if not set.
	Get7BitMode() *bool
	// Get8BitMode returns true if the client set 8 bit mode (CS8), false if disabled, nil if not set.
	Get8BitMode() *bool
	// GetEnableParity returns true if the client set to enable parity (PARENB), false if disabled, nil if not set.
	GetEnableParity() *bool
	// GetOddParity returns true if the client set odd parity (PARODD), false if even, nil if not set.
	GetOddParity() *bool
	// GetInputSpeed returns the input baud rate in bits per second, nil if not set.
	GetInputSpeed() *uint32
	// GetOutputSpeed returns the output baud rate in bits per second, nil if not set.
	GetOutputSpeed() *uint32
}

// SessionChannel is a channel of the "session" type used for interactive and non-interactive sessions
type SessionChannel interface {
	// OnEnvRequest is called when the client requests an environment variable to be set. The implementation can return an
	//              error to reject the request.
	OnEnvRequest(name string, value string) error

	// OnExecRequest is called when the client request a program to be executed. The implementation can return an error
	//               to reject the request.
	OnExecRequest(program string) error

	// OnPtyRequest is called when the client requests an interactive terminal to be allocated. The implementation can
	//              return an error to reject the request.
	//
	// term is the terminal name. This is usually set in the TERM environment variable.
	// columns is the number of columns in the terminal.
	// rows is the number of rows in the terminal.
	// width is the width of the terminal in pixels.
	// height is the height of a terminal in pixels.
	// modelist are the encoded terminal modes the client desires.
	OnPtyRequest(term string, columns uint32, rows uint32, width uint32, height uint32, modeList TerminalModes) error

	// OnShell is called when the client requests a shell to be started. The implementation can return an error to
	//         reject the request. The implementation should send the IO handling into background. It should also
	//         respect the shutdown context on the Handler.
	//
	// stdin is a reader for the shell or program to read the stdin.
	// stdout is a writer for the shell or program standard output.
	// stderr is a writer for the shell or program standard error.
	// onExit is a callback to send the exit status back to the client.
	OnShell(stdin io.Reader, stdout io.Writer, stderr io.Writer, onExit func(exitStatus uint32)) error

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
	OnWindow(columns uint32, rows uint32, width uint32, height uint32) error
}
