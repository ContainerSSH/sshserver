package v2

import (
	"fmt"
)

var supportedMACs = []stringer{
	MACHMACSHA2256ETM, MACHMACSHA2256, MACHMACSHA196, MACHMACSHA1,
}

// MAC are the SSH mac algorithms.
type MAC string

// MAC are the SSH mac algorithms.
const (
	MACHMACSHA2256ETM MAC = "hmac-sha2-256-etm@openssh.com"
	MACHMACSHA2256    MAC = "hmac-sha2-256"
	MACHMACSHA1       MAC = "hmac-sha1"
	MACHMACSHA196     MAC = "hmac-sha1-96"
)

// String creates a string representation.
func (m MAC) String() string {
	return string(m)
}

func (m MAC) Validate() error {
	if m == "" {
		return fmt.Errorf("empty MAC")
	}
	for _, algo := range supportedMACs {
		if algo == m {
			return nil
		}
	}
	return fmt.Errorf("MAC not supported: %s", m)
}
