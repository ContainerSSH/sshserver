package v2

import (
	"github.com/containerssh/service"
)

// Server is the main SSH server interface, compatible with the Service library. It should always be used in conjunction
// with the Lifecycle interface from the service library.
type Server interface {
	service.Service
}
