package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/containerssh/log"

	"github.com/containerssh/http"
)

//region Config

// OIDCConfig is the configuration for OpenID Connect authentication.
type OIDCConfig struct {
	http.ClientConfiguration

	// DeviceFlow enables or disables using the OIDC device flow.
	DeviceFlow bool `json:"deviceFlow" yaml:"deviceFlow" default:"true"`
	// AuthorizationCodeFlow enables or disables the OIDC authorization code flow.
	AuthorizationCodeFlow bool `json:"authorizationCodeFlow" yaml:"authorizationCodeFlow" default:"true"`
}

func (o *OIDCConfig) Validate() error {
	if !o.DeviceFlow && !o.AuthorizationCodeFlow {
		return fmt.Errorf("at least one of deviceFlow or authorizationCodeFlow must be enabled")
	}
	return o.ClientConfiguration.Validate()
}

//endregion

//region Provider

func newOIDCProvider(config ClientConfig, logger log.Logger) (OAuth2Provider, error) {
	return &oidcProvider{
		config: config,
		logger: logger,
	}, nil
}

type oidcProvider struct {
	config ClientConfig
	logger log.Logger
}

func (o *oidcProvider) SupportsDeviceFlow() bool {
	return o.config.OAuth2.OIDC.DeviceFlow
}

func (o *oidcProvider) GetDeviceFlow(connectionID string, username string) (OAuth2DeviceFlow, error) {
	flow, err := o.createFlow(connectionID, username)
	if err != nil {
		return nil, err
	}

	return &oidcDeviceFlow{
		flow,
	}, nil
}

func (o *oidcProvider) SupportsAuthorizationCodeFlow() bool {
	return o.config.OAuth2.OIDC.AuthorizationCodeFlow
}

func (o *oidcProvider) GetAuthorizationCodeFlow(connectionID string, username string) (
	OAuth2AuthorizationCodeFlow,
	error,
) {
	flow, err := o.createFlow(connectionID, username)
	if err != nil {
		return nil, err
	}

	return &oidcAuthorizationCodeFlow{
		flow,
	}, nil
}

func (o *oidcProvider) createFlow(connectionID string, username string) (oidcFlow, error) {
	logger := o.logger.WithLabel("connectionID", connectionID).WithLabel("username", username)

	client, err := http.NewClient(o.config.OAuth2.OIDC.ClientConfiguration, logger)
	if err != nil {
		return oidcFlow{}, log.WrapUser(
			err,
			EGitHubHTTPClientCreateFailed,
			"Authentication currently unavailable.",
			"Cannot create GitHub device flow authenticator because the HTTP client configuration failed.",
		)
	}

	flow := oidcFlow{
		provider:     o,
		connectionID: connectionID,
		username:     username,
		logger:       logger,
		client:       client,
	}
	return flow, nil
}

//endregion

//region Flow

type oidcFlow struct {
	provider     *oidcProvider
	connectionID string
	username     string
	logger       log.Logger
	client       http.Client
}

func (o *oidcFlow) Deauthorize(ctx context.Context) {
	panic("implement me")
}

//endregion

//region Device flow

type oidcDeviceFlow struct {
	oidcFlow
}

func (o *oidcDeviceFlow) GetAuthorizationURL(ctx context.Context) (
	verificationLink string,
	userCode string,
	expiration time.Duration,
	err error,
) {
	panic("implement me")
}

func (o *oidcDeviceFlow) Verify(ctx context.Context) (map[string]string, error) {
	panic("implement me")
}

//endregion

//region Authorization code flow

type oidcAuthorizationCodeFlow struct {
	oidcFlow
}

func (o *oidcAuthorizationCodeFlow) GetAuthorizationURL(ctx context.Context) (string, error) {
	panic("implement me")
}

func (o *oidcAuthorizationCodeFlow) Verify(
	ctx context.Context,
	state string,
	authorizationCode string,
) (map[string]string, error) {
	panic("implement me")
}

//endregion