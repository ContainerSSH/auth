package auth

import (
	"github.com/containerssh/http"
	"github.com/containerssh/log"
)

// NewServer returns a complete HTTP server that responds to the authentication requests.
//goland:noinspection GoUnusedExportedFunction
func NewServer(
	configuration http.ServerConfiguration,
	h Handler,
	logger log.Logger,
	onReady func(),
) (http.Server, error) {
	return http.NewServer(
		configuration,
		NewHandler(h, logger),
		onReady,
		logger,
	)
}
