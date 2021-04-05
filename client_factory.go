package auth

import (
	"fmt"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
	"github.com/containerssh/metrics"
)

// NewHttpAuthClient creates a new HTTP authentication client
//goland:noinspection GoUnusedExportedFunction
func NewHttpAuthClient(
	config ClientConfig,
	logger log.Logger,
	metrics metrics.Collector,
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
	backendRequestsMetric := metrics.MustCreateCounter(
		MetricNameAuthBackendRequests,
		"requests",
		"The number of requests sent to the configuration server.",
	)
	backendFailureMetric := metrics.MustCreateCounter(
		MetricNameAuthBackendFailure,
		"requests",
		"The number of request failures to the configuration server.",
	)
	authSuccessMetric := metrics.MustCreateCounterGeo(
		MetricNameAuthSuccess,
		"requests",
		"The number of successful authentications.",
	)
	authFailureMetric := metrics.MustCreateCounterGeo(
		MetricNameAuthFailure,
		"requests",
		"The number of failed authentications.",
	)
	return &httpAuthClient{
		enablePassword:        config.Password,
		enablePubKey:          config.PubKey,
		timeout:               config.AuthTimeout,
		httpClient:            realClient,
		logger:                logger,
		metrics:               metrics,
		backendRequestsMetric: backendRequestsMetric,
		backendFailureMetric:  backendFailureMetric,
		authSuccessMetric:     authSuccessMetric,
		authFailureMetric:     authFailureMetric,
	}, nil
}
