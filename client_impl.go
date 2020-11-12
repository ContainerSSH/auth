package auth

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
)

type httpAuthClient struct {
	httpClient http.Client
	endpoint   string
	logger     log.Logger
}

func (client *httpAuthClient) Password(
	username string,
	password []byte,
	sessionId []byte,
	remoteAddr net.IP,
) (success bool, err error) {
	authRequest := PasswordAuthRequest{
		Username:      username,
		RemoteAddress: remoteAddr.String(),
		SessionID:     base64.StdEncoding.EncodeToString(sessionId),
		Password:      password,
	}
	authResponse := &ResponseBody{}
	if err := client.authServerRequest(client.endpoint+"/password", authRequest, authResponse); err != nil {
		return false, err
	}
	return authResponse.Success, nil
}

func (client *httpAuthClient) PubKey(
	username string,
	pubKey []byte,
	sessionId []byte,
	remoteAddr net.IP,
) (bool, error) {
	authRequest := PublicKeyAuthRequest{
		Username:      username,
		RemoteAddress: remoteAddr.String(),
		SessionID:     base64.StdEncoding.EncodeToString(sessionId),
		PublicKey:     pubKey,
	}
	authResponse := &ResponseBody{}
	if err := client.authServerRequest(client.endpoint+"/pubkey", authRequest, authResponse); err != nil {
		return false, err
	}
	return authResponse.Success, nil
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
