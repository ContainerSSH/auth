package auth

import (
	"fmt"

	"github.com/containerssh/log"
	"github.com/containerssh/metrics"
	"github.com/containerssh/service"
)

func NewClient(
	config ClientConfig,
	logger log.Logger,
	metrics metrics.Collector,
) (Client, service.Service, error) {
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}
	switch config.Method {
	case MethodWebhook:
		client, err := NewHttpAuthClient(config, logger, metrics)
		return client, nil, err
	case MethodOAuth2:
		return NewOAuth2Client(config, logger, metrics)
	default:
		return nil, nil, fmt.Errorf("unsupported method: %s", config.Method)
	}
}
