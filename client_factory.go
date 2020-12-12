package auth

import (
	"fmt"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
)

// NewHttpAuthClient creates a new HTTP authentication client
//goland:noinspection GoUnusedExportedFunction
func NewHttpAuthClient(
	config ClientConfig,
	logger log.Logger,
) (Client, error) {
	if config.URL == "" {
		return nil, fmt.Errorf("no authentication server URL provided")
	}
	realClient, err := http.NewClient(
		config.ClientConfiguration,
		logger,
	)
	if err != nil {
		return nil, err
	}
	return &httpAuthClient{
		httpClient: realClient,
		logger:     logger,
	}, nil
}
