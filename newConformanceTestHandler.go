package v2

func newConformanceTestHandler(backend NetworkConnectionHandler) *conformanceTestHandler {
	return &conformanceTestHandler{backend: backend}
}
