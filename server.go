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
) (http.Server, error) {
	return http.NewServer(
		"Auth Server",
		configuration,
		NewHandler(h, logger),
		logger,
		func(url string) {
			logger.Info(log.NewMessage(MAuthServerAvailable, "The authentication server is now available at %s", url))
		},
	)
}
