package auth

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
	"github.com/containerssh/metrics"
)

type httpAuthClient struct {
	timeout               time.Duration
	httpClient            http.Client
	endpoint              string
	logger                log.Logger
	metrics               metrics.Collector
	backendRequestsMetric metrics.SimpleCounter
	backendFailureMetric  metrics.SimpleCounter
	authSuccessMetric     metrics.GeoCounter
	authFailureMetric     metrics.GeoCounter
	enablePassword        bool
	enablePubKey          bool
}

func (client *httpAuthClient) Password(
	username string,
	password []byte,
	connectionID string,
	remoteAddr net.IP,
) (bool, error) {
	if !client.enablePassword {
		err := log.UserMessage(
			EDisabled,
			"Password authentication failed.",
			"Password authentication is disabled.",
		)
		client.logger.Debug(err)
		return false, err
	}
	url := client.endpoint + "/password"
	method := "Password"
	authType := "password"
	authRequest := PasswordAuthRequest{
		Username:      username,
		RemoteAddress: remoteAddr.String(),
		ConnectionID:  connectionID,
		SessionID:     connectionID,
		Password:      password,
	}

	return client.processAuthWithRetry(username, method, authType, connectionID, url, authRequest, remoteAddr)
}

func (client *httpAuthClient) PubKey(
	username string,
	pubKey string,
	connectionID string,
	remoteAddr net.IP,
) (bool, error) {
	if !client.enablePubKey {
		err := log.UserMessage(
			EDisabled,
			"Public key authentication failed.",
			"Public key authentication is disabled.",
		)
		client.logger.Debug(err)
		return false, err
	}
	url := client.endpoint + "/pubkey"
	authRequest := PublicKeyAuthRequest{
		Username:      username,
		RemoteAddress: remoteAddr.String(),
		ConnectionID:  connectionID,
		SessionID:     connectionID,
		PublicKey:     pubKey,
	}
	method := "Public key"
	authType := "pubkey"

	return client.processAuthWithRetry(username, method, authType, connectionID, url, authRequest, remoteAddr)
}

func (client *httpAuthClient) processAuthWithRetry(
	username string,
	method string,
	authType string,
	connectionID string,
	url string,
	authRequest interface{},
	remoteAddr net.IP,
) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), client.timeout)
	defer cancel()
	var lastError error
	var lastLabels []metrics.MetricLabel
	logger := client.logger.
		WithLabel("connectionId", connectionID).
		WithLabel("username", username).
		WithLabel("url", url).
		WithLabel("authtype", authType)
loop:
	for {
		lastLabels = []metrics.MetricLabel{
			metrics.Label("authtype", authType),
		}
		if lastError != nil {
			lastLabels = append(
				lastLabels,
				metrics.Label("retry", "1"),
			)
		} else {
			lastLabels = append(
				lastLabels,
				metrics.Label("retry", "0"),
			)
		}
		client.logAttempt(logger, method, lastLabels)

		authResponse := &ResponseBody{}
		lastError = client.authServerRequest(url, authRequest, authResponse)
		if lastError == nil {
			client.logAuthResponse(logger, method, authResponse, lastLabels, remoteAddr)
			return authResponse.Success, nil
		}
		reason := client.getReason(lastError)
		lastLabels = append(lastLabels, metrics.Label("reason", reason))
		client.logTemporaryFailure(logger, lastError, method, reason, lastLabels)
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(10 * time.Second):
		}
	}
	return client.logAndReturnPermanentFailure(lastError, method, lastLabels, logger)
}

func (client *httpAuthClient) logAttempt(logger log.Logger, method string, lastLabels []metrics.MetricLabel) {
	logger.Debug(
		log.NewMessage(
			MAuth,
			"%s authentication request",
			method,
		),
	)
	client.backendRequestsMetric.Increment(lastLabels...)
}

func (client *httpAuthClient) logAndReturnPermanentFailure(
	lastError error,
	method string,
	lastLabels []metrics.MetricLabel,
	logger log.Logger,
) (bool, error) {
	err := log.Wrap(
		lastError,
		EAuthBackendError,
		"Backend request for %s authentication failed, giving up",
		strings.ToLower(method),
	)
	client.backendFailureMetric.Increment(
		append(
			[]metrics.MetricLabel{
				metrics.Label("type", "hard"),
			}, lastLabels...,
		)...,
	)
	logger.Error(err)
	return false, err
}

func (client *httpAuthClient) logTemporaryFailure(
	logger log.Logger,
	lastError error,
	method string,
	reason string,
	lastLabels []metrics.MetricLabel,
) {
	logger.Debug(
		log.Wrap(
			lastError,
			EAuthBackendError,
			"%s authentication request to backend failed, retrying in 10 seconds",
			method,
		).
			Label("reason", reason),
	)
	client.backendFailureMetric.Increment(
		append(
			[]metrics.MetricLabel{
				metrics.Label("type", "soft"),
			}, lastLabels...,
		)...,
	)
}

func (client *httpAuthClient) getReason(lastError error) string {
	var typedErr log.Message
	reason := log.EUnknownError
	if errors.As(lastError, &typedErr) {
		reason = typedErr.Code()
	}
	return reason
}

func (client *httpAuthClient) logAuthResponse(
	logger log.Logger,
	method string,
	authResponse *ResponseBody,
	labels []metrics.MetricLabel,
	remoteAddr net.IP,
) {
	if authResponse.Success {
		logger.Debug(
			log.NewMessage(
				MAuthSuccessful,
				"%s authentication successful",
				method,
			),
		)
		client.authSuccessMetric.Increment(remoteAddr, labels...)
	} else {
		logger.Debug(
			log.NewMessage(
				EAuthFailed,
				"%s authentication failed",
				method,
			),
		)
		client.authFailureMetric.Increment(remoteAddr, labels...)
	}
}

func (client *httpAuthClient) authServerRequest(endpoint string, requestObject interface{}, response interface{}) error {
	statusCode, err := client.httpClient.Post(endpoint, requestObject, response)
	if err != nil {
		return err
	}
	if statusCode != 200 {
		return log.UserMessage(
			EInvalidStatus,
			"Cannot authenticate at this time.",
			"auth server responded with an invalid status code: %d",
			statusCode,
		)
	}
	return nil
}
