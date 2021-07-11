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
	if config.Method != MethodWebhook {
		return nil, fmt.Errorf("authentication is not set to webhook")
	}
	if err := config.Validate(); err != nil {
		return nil, err
	}

	if config.URL != "" {
		logger.Warning(log.NewMessage(
			EDeprecated,
			"The auth.url setting is deprecated, please switch to using auth.webhook.url. See https://containerssh.io/deprecations/authurl for details.",
		))
		//goland:noinspection GoDeprecation
		config.Webhook.realClientConfiguration = config.ClientConfiguration
		//goland:noinspection GoDeprecation
		config.Webhook.Password = config.Password
		//goland:noinspection GoDeprecation
		config.Webhook.PubKey = config.PubKey
		//goland:noinspection GoDeprecation
		config.ClientConfiguration = http.ClientConfiguration{}
	}

	realClient, err := http.NewClient(
		config.Webhook.realClientConfiguration,
		logger,
	)
	if err != nil {
		return nil, err
	}

	backendRequestsMetric, backendFailureMetric, authSuccessMetric, authFailureMetric := createMetrics(metrics)
	return &httpAuthClient{
		enablePassword: config.Webhook.Password,
		enablePubKey: config.Webhook.PubKey,
		timeout: config.AuthTimeout,
		httpClient: realClient,
		logger: logger,
		metrics: metrics,
		backendRequestsMetric: backendRequestsMetric,
		backendFailureMetric: backendFailureMetric,
		authSuccessMetric: authSuccessMetric,
		authFailureMetric: authFailureMetric,
	}, nil
}

func createMetrics(metrics metrics.Collector) (
	metrics.Counter,
	metrics.Counter,
	metrics.GeoCounter,
	metrics.GeoCounter,
) {
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
	return backendRequestsMetric, backendFailureMetric, authSuccessMetric, authFailureMetric
}
