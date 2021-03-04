package auth

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
)

type httpAuthClient struct {
	timeout    time.Duration
	httpClient http.Client
	endpoint   string
	logger     log.Logger
}

func (client *httpAuthClient) Password(
	username string,
	password []byte,
	connectionID string,
	remoteAddr net.IP,
) (bool, error) {
	url := client.endpoint + "/password"
	method := "Password"
	authRequest := PasswordAuthRequest{
		Username:      username,
		RemoteAddress: remoteAddr.String(),
		SessionID:     connectionID,
		Password:      password,
	}

	return client.processAuthWithRetry(username, method, connectionID, url, authRequest)
}

func (client *httpAuthClient) PubKey(
	username string,
	pubKey string,
	connectionID string,
	remoteAddr net.IP,
) (bool, error) {
	url := client.endpoint + "/pubkey"
	authRequest := PublicKeyAuthRequest{
		Username:      username,
		RemoteAddress: remoteAddr.String(),
		SessionID:     connectionID,
		PublicKey:     pubKey,
	}
	method := "Public key"

	return client.processAuthWithRetry(username, method, connectionID, url, authRequest)
}

func (client *httpAuthClient) processAuthWithRetry(
	username string,
	method string,
	connectionID string,
	url string,
	authRequest interface{},
) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), client.timeout)
	defer cancel()
	var lastError error
loop:
	for {
		client.logger.Debug(
			log.NewMessage(
				MAuth,
				"%s authentication request",
				method,
			).Label("connectionId", connectionID).Label("username", username).Label("url", url),
		)
		authResponse := &ResponseBody{}
		lastError = client.authServerRequest(url, authRequest, authResponse)
		if lastError == nil {
			client.logAuthResponse(username, method, connectionID, url, authResponse)
			return authResponse.Success, nil
		}
		client.logger.Debug(
			log.Wrap(
				lastError,
				EAuthBackendError,
				"%s authentication request to backend failed, retrying in 10 seconds",
				method,
			).
				Label("connectionId", connectionID).
				Label("username", username).
				Label("url", url).
				Label("method", strings.ToLower(method)),
		)
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(10 * time.Second):
		}
	}
	err := log.Wrap(
		lastError,
		EAuthBackendError,
		"Backend request for %s authentication failed, giving up",
		strings.ToLower(method),
	).
		Label("connectionId", connectionID).
		Label("username", username).
		Label("url", url).
		Label("method", strings.ToLower(method))
	client.logger.Error(err)
	return false, err
}

func (client *httpAuthClient) logAuthResponse(
	username string,
	method string,
	connectionID string,
	url string,
	authResponse *ResponseBody,
) {
	if authResponse.Success {
		client.logger.Debug(
			log.NewMessage(
				MAuthSuccessful,
				"%s authentication successful",
				method,
			).
				Label("connectionId", connectionID).
				Label("username", username).
				Label("url", url).
				Label("method", strings.ToLower(method)),
		)
	} else {
		client.logger.Debug(
			log.NewMessage(
				EAuthFailed,
				"%s authentication failed",
				method,
			).
				Label("connectionId", connectionID).
				Label("username", username).
				Label("url", url).
				Label("method", strings.ToLower(method)),
		)
	}
}

func (client *httpAuthClient) authServerRequest(endpoint string, requestObject interface{}, response interface{}) error {
	statusCode, err := client.httpClient.Post(endpoint, requestObject, response)
	if err != nil {
		return err
	}
	if statusCode != 200 {
		return fmt.Errorf("auth server responded with an invalid status code (%d)", statusCode)
	}
	return nil
}
