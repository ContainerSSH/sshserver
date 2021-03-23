package sshserver

import (
	"fmt"
	"regexp"
)

var serverVersionRegexp = regexp.MustCompile(`^SSH-2.0-[a-zA-Z0-9]+(| [a-zA-Z0-9- _.]+)$`)

// ServerVersion is a string that is issued to the client when connecting.
type ServerVersion string

// Validate checks if the server version conforms to RFC 4253 section 4.2.
// See https://tools.ietf.org/html/rfc4253#page-4
func (s ServerVersion) Validate() error {
	if !serverVersionRegexp.MatchString(string(s)) {
		return fmt.Errorf("invalid server version string (%s), see https://tools.ietf.org/html/rfc4253#page-4 section 4.2. for details", s)
	}
	return nil
}

// String returns a string from the ServerVersion.
func (s ServerVersion) String() string {
	return string(s)
}
