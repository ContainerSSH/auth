package auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/containerssh/log"
	"github.com/containerssh/structutils"

	"github.com/containerssh/http"
)

//region GitHubConfig

// GitHubConfig is the configuration structure for GitHub authentication.
//goland:noinspection GoVetStructTag
type GitHubConfig struct {
	// URL is the base GitHub URL. Change this for GitHub Enterprise.
	URL string `json:"url" yaml:"url" default:"https://github.com"`
	// APIURL is the GitHub API URL. Change this for GitHub Enterprise.
	APIURL string `json:"apiurl" yaml:"apiurl" default:"https://api.github.com"`

	GitHubCACert `json:",inline" yaml:",inline"`

	// ClientCert is a PEM containing an x509 certificate to present to the server or a file name containing the PEM.
	ClientCert string `json:"cert" yaml:"cert" comment:"Client certificate file in PEM format."`

	// ClientKey is a PEM containing a private key to use to connect the server or a file name containing the PEM.
	ClientKey string `json:"key" yaml:"key" comment:"Client key file in PEM format."`

	// TLSVersion is the minimum TLS version to use.
	TLSVersion http.TLSVersion `json:"tlsVersion" yaml:"tlsVersion" default:"1.3"`

	// ECDHCurves is the list of curve algorithms to support.
	ECDHCurves http.ECDHCurveList `json:"curves" yaml:"curves" default:"[\"x25519\",\"secp256r1\",\"secp384r1\",\"secp521r1\"]"`

	// CipherSuites is a list of supported cipher suites.
	CipherSuites http.CipherSuiteList `json:"cipher" yaml:"cipher" default:"[\"TLS_AES_128_GCM_SHA256\",\"TLS_AES_256_GCM_SHA384\",\"TLS_CHACHA20_POLY1305_SHA256\",\"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256\",\"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256\"]"`

	// EnforceUsername requires that the GitHub username and the entered SSH username match. If this is set to false
	// the configuration server has to handle the GITHUB_USER connection parameter in order to obtain the correct
	// username as the SSH username cannot be trusted.
	EnforceUsername bool `json:"enforceUsername" yaml:"enforceUsername" default:"true"`
	// RequireOrgMembership checks if the user is part of the specified organization on GitHub. This requires the
	// read:org scope to be granted by the user. If the user does not grant this scope the authentication fails.
	RequireOrgMembership string `json:"requireOrgMembership" yaml:"requireOrgMembership"`
	// Require2FA requires the user to have two factor authentication enabled when logging in to this server. This
	// requires the read:user scope to be granted by the user. If the user does not grant this scope the authentication
	// fails.
	Require2FA bool `json:"require2FA" yaml:"require2FA"`

	// ExtraScopes asks the user to grant extra scopes to ContainerSSH. This is useful when the configuration server
	// needs these scopes to operate.
	ExtraScopes []string `json:"extraScopes" yaml:"extraScopes"`
	// EnforceScopes rejects the user authentication if the user fails to grant the scopes requested in extraScopes.
	EnforceScopes bool `json:"enforceScopes" yaml:"enforceScopes"`

	// RequestTimeout is the timeout for individual HTTP requests.
	RequestTimeout time.Duration `json:"timeout" yaml:"timeout" default:"10s"`

	parsedURL           *url.URL                 `json:"-"`
	parsedAPIURL        *url.URL                 `json:"-"`
	wwwClientConfig     http.ClientConfiguration `json:"-"`
	jsonWWWClientConfig http.ClientConfiguration `json:"-"`
	apiClientConfig     http.ClientConfiguration `json:"-"`
}

func (c *GitHubConfig) Validate() (err error) {
	if c.parsedURL, err = url.Parse(c.URL); err != nil {
		return fmt.Errorf("invalid GitHub URL: %s (%w)", c.URL, err)
	}
	structutils.Defaults(&c.wwwClientConfig)
	c.wwwClientConfig.URL = c.URL
	c.wwwClientConfig.CACert = c.CACert
	c.wwwClientConfig.Timeout = c.RequestTimeout
	c.wwwClientConfig.RequestEncoding = http.RequestEncodingWWWURLEncoded
	if err := c.wwwClientConfig.Validate(); err != nil {
		return err
	}

	structutils.Defaults(&c.jsonWWWClientConfig)
	c.jsonWWWClientConfig.URL = c.URL
	c.jsonWWWClientConfig.CACert = c.CACert
	c.jsonWWWClientConfig.Timeout = c.RequestTimeout
	c.jsonWWWClientConfig.RequestEncoding = http.RequestEncodingJSON
	if err := c.jsonWWWClientConfig.Validate(); err != nil {
		return err
	}

	if c.parsedAPIURL, err = url.Parse(c.APIURL); err != nil {
		return fmt.Errorf("invalid GitHub API URL: %s (%w)", c.APIURL, err)
	}
	structutils.Defaults(&c.apiClientConfig)
	c.apiClientConfig.URL = c.APIURL
	c.apiClientConfig.CACert = c.CACert
	c.apiClientConfig.Timeout = c.RequestTimeout
	c.apiClientConfig.RequestEncoding = http.RequestEncodingJSON
	if err := c.apiClientConfig.Validate(); err != nil {
		return err
	}

	return nil
}

//endregion

//region gitHubProvider

// newGitHubProvider creates a new, GitHub-specific OAuth2 provider.
func newGitHubProvider(config ClientConfig, logger log.Logger) (OAuth2Provider, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid GitHub configuration (%w)", err)
	}

	return &gitHubProvider{
		logger:                logger,
		url:                   config.OAuth2.GitHub.parsedURL,
		apiURL:                config.OAuth2.GitHub.parsedAPIURL,
		clientID:              config.OAuth2.ClientID,
		clientSecret:          config.OAuth2.ClientSecret,
		requiredOrgMembership: config.OAuth2.GitHub.RequireOrgMembership,
		scopes:                config.OAuth2.GitHub.ExtraScopes,
		enforceUsername:       config.OAuth2.GitHub.EnforceUsername,
		enforceScopes:         config.OAuth2.GitHub.EnforceScopes,
		require2FA:            config.OAuth2.GitHub.Require2FA,
		wwwClientConfig:       config.OAuth2.GitHub.wwwClientConfig,
		jsonWWWClientConfig:   config.OAuth2.GitHub.jsonWWWClientConfig,
		apiClientConfig:       config.OAuth2.GitHub.apiClientConfig,
	}, nil
}

type gitHubProvider struct {
	logger                log.Logger
	url                   *url.URL
	apiURL                *url.URL
	clientID              string
	clientSecret          string
	requiredOrgMembership string
	scopes                []string
	enforceScopes         bool
	require2FA            bool
	enforceUsername       bool
	wwwClientConfig       http.ClientConfiguration
	jsonWWWClientConfig   http.ClientConfiguration
	apiClientConfig       http.ClientConfiguration
}

func (p *gitHubProvider) SupportsDeviceFlow() bool {
	return true
}

func (p *gitHubProvider) GetDeviceFlow(connectionID string, username string) (OAuth2DeviceFlow, error) {
	flow, err := p.createFlow(connectionID, username)
	if err != nil {
		return nil, err
	}

	return &gitHubDeviceFlow{
		gitHubFlow: flow,
		interval:   10 * time.Second,
	}, nil
}

func (p *gitHubProvider) SupportsAuthorizationCodeFlow() bool {
	return true
}

func (p *gitHubProvider) GetAuthorizationCodeFlow(connectionID string, username string) (
	OAuth2AuthorizationCodeFlow,
	error,
) {
	flow, err := p.createFlow(connectionID, username)
	if err != nil {
		return nil, err
	}

	return &gitHubAuthorizationCodeFlow{
		gitHubFlow: flow,
	}, nil
}

func (p *gitHubProvider) createFlow(connectionID string, username string) (
	gitHubFlow,
	error,
) {
	logger := p.logger.WithLabel("connectionID", connectionID).WithLabel("username", username)

	client, err := http.NewClient(p.wwwClientConfig, logger)
	if err != nil {
		return gitHubFlow{}, log.WrapUser(
			err,
			EGitHubHTTPClientCreateFailed,
			"Authentication currently unavailable.",
			"Cannot create GitHub device flow authenticator because the HTTP client configuration failed.",
		)
	}

	jsonClient, err := http.NewClient(p.jsonWWWClientConfig, logger)
	if err != nil {
		return gitHubFlow{}, log.WrapUser(
			err,
			EGitHubHTTPClientCreateFailed,
			"Authentication currently unavailable.",
			"Cannot create GitHub device flow authenticator because the HTTP client configuration failed.",
		)
	}

	flow := gitHubFlow{
		provider:     p,
		clientID:     p.clientID,
		clientSecret: p.clientSecret,
		connectionID: connectionID,
		username:     username,
		logger:       logger,
		client:       client,
		jsonClient:   jsonClient,
		apiClientConfig: p.apiClientConfig,
	}
	return flow, nil
}

func (p *gitHubProvider) getScope() string {
	scopes := p.scopes
	if p.requiredOrgMembership != "" {
		foundOrgRead := false
		for _, scope := range scopes {
			if scope == "org" || scope == "read:org" {
				foundOrgRead = true
				break
			}
		}
		if !foundOrgRead {
			scopes = append(scopes, "read:org")
		}
	}
	if p.require2FA {
		foundUserRead := false
		for _, scope := range scopes {
			if scope == "user" || scope == "read:user" {
				foundUserRead = true
				break
			}
		}
		if !foundUserRead {
			scopes = append(scopes, "read:user")
		}
	}
	return strings.Join(scopes, ",")
}

type gitHubDeleteAccessTokenRequest struct {
	AccessToken string `json:"access_token"`
}

type gitHubDeleteAccessTokenResponse struct {
}

type gitHubAccessTokenRequest struct {
	ClientID     string `json:"client_id" schema:"client_id,required"`
	ClientSecret string `json:"client_secret,omitempty" schema:"client_secret"`
	Code         string `json:"code,omitempty" schema:"code"`
	DeviceCode   string `json:"device_code,omitempty" schema:"device_code"`
	GrantType    string `json:"grant_type,omitempty" schema:"grant_type"`
	State        string `json:"state,omitempty" schema:"state"`
}

type gitHubAccessTokenResponse struct {
	AccessToken      string `json:"access_token,omitempty"`
	Scope            string `json:"scope,omitempty"`
	TokenType        string `json:"token_type,omitempty"`
	Error            string `json:"error,omitempty"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
	Interval         uint   `json:"interval,omitempty"`
}

type gitHubUserResponse struct {
	Login                   string `json:"login"`
	ID                      uint64 `json:"id"`
	NodeID                  string `json:"node_id"`
	AvatarURL               string `json:"avatar_url"`
	ProfileURL              string `json:"html_url"`
	Name                    string `json:"name"`
	Company                 string `json:"company"`
	BlogURL                 string `json:"blog"`
	Location                string `json:"location"`
	Email                   string `json:"email"`
	Bio                     string `json:"bio"`
	TwitterUsername         string `json:"twitter_username"`
	TwoFactorAuthentication *bool  `json:"two_factor_authentication"`
}

// endregion

//region gitHubFlow
type gitHubFlow struct {
	provider        *gitHubProvider
	connectionID    string
	username        string
	accessToken     string
	clientID        string
	clientSecret    string
	logger          log.Logger
	client          http.Client
	jsonClient      http.Client
	apiClientConfig http.ClientConfiguration
}

func (g *gitHubFlow) checkGrantedScopes(scope string) error {
	grantedScopes := strings.Split(scope, ",")
	if g.provider.enforceScopes {
		for _, requiredScope := range g.provider.scopes {
			scopeGranted := false
			requiredScopeParts := strings.Split(requiredScope, ":")
			for _, grantedScope := range grantedScopes {
				if grantedScope == requiredScope || (len(requiredScopeParts) > 1 && requiredScopeParts[0] == grantedScope) {
					scopeGranted = true
					break
				}
			}
			if !scopeGranted {
				err := log.UserMessage(
					EGitHubRequiredScopeNotGranted,
					fmt.Sprintf("You have not granted us the required %s permission.", requiredScope),
					"The user has not granted the %s permission.",
					requiredScope,
				)
				g.logger.Debug(err)
				return err
			}
		}
	}
	if g.provider.requiredOrgMembership != "" {
		for _, grantedScope := range grantedScopes {
			if grantedScope == "org" || grantedScope == "read:org" {
				return nil
			}
		}
		err := log.UserMessage(
			EGitHubRequiredScopeNotGranted,
			"You have not granted us permissions to read your organization memberships required for login.",
			"The user has not granted the org or read:org memberships required to validate the organization member ship.",
		)
		g.logger.Debug(err)
		return err
	}
	return nil
}

func (g *gitHubFlow) getIdentity(
	ctx context.Context,
	username string,
	accessToken string,
) (map[string]string, error) {
	var statusCode int
	var lastError error
	apiClient, err := g.getAPIClient(accessToken, false)
	if err != nil {
		return nil, err
	}
loop:
	for {
		response := &gitHubUserResponse{}
		statusCode, lastError = apiClient.Get("/user", response)
		if lastError == nil {
			if statusCode == 200 {
				if g.provider.enforceUsername && response.Login != username {
					err := log.UserMessage(
						EUsernameDoesNotMatch,
						"The username entered in your SSH client does not match your GitHub login.",
						"The user's username entered in the SSH username and on GitHub login do not match, but enforceUsername is enabled.",
					)
					g.logger.Debug(err)
					return nil, err
				}

				result := map[string]string{}
				if response.TwoFactorAuthentication != nil {
					if *response.TwoFactorAuthentication {
						result["GITHUB_2FA"] = "true"
					} else {
						if g.provider.require2FA {
							err := log.UserMessage(
								EGitHubNo2FA,
								"Please enable two-factor authentication on GitHub to access this server.",
								"The user does not have two-factor authentication enabled on their GitHub account.",
							)
							g.logger.Debug(err)
							return nil, err
						}
						result["GITHUB_2FA"] = "false"
					}
				} else if g.provider.require2FA {
					err := log.UserMessage(
						EGitHubNo2FA,
						"Please grant the read:user permission so we can check your 2FA status.",
						"The user did not provide the read:user permission to read the 2FA status.",
					)
					g.logger.Debug(err)
					return nil, err
				}
				result["GITHUB_METHOD"] = "device"
				result["GITHUB_TOKEN"] = accessToken
				result["GITHUB_LOGIN"] = response.Login
				result["GITHUB_ID"] = fmt.Sprintf("%d", response.ID)
				result["GITHUB_NODE_ID"] = response.NodeID
				result["GITHUB_NAME"] = response.Name
				result["GITHUB_AVATAR_URL"] = response.AvatarURL
				result["GITHUB_BIO"] = response.Bio
				result["GITHUB_COMPANY"] = response.Company
				result["GITHUB_EMAIL"] = response.Email
				result["GITHUB_BLOG_URL"] = response.BlogURL
				result["GITHUB_LOCATION"] = response.Location
				result["GITHUB_TWITTER_USERNAME"] = response.TwitterUsername
				result["GITHUB_PROFILE_URL"] = response.ProfileURL
				result["GITHUB_AVATAR_URL"] = response.AvatarURL
				if g.provider.enforceUsername && response.Login != username {
					return nil, log.UserMessage(EGitHubUsernameDoesNotMatch, "Your GitHub username does not match your SSH login. Please try again and specify your GitHub username when connecting.", "User did not use their GitHub username in the SSH login.")
				}
				return result, nil
			} else {
				g.logger.Debug(
					log.NewMessage(
						EGitHubUserRequestFailed,
						"Request to GitHub user endpoint failed, non-200 response code (%d), retrying in 10 seconds...",
						statusCode,
					),
				)
			}
		} else {
			g.logger.Debug(
				log.Wrap(
					lastError,
					EGitHubUserRequestFailed,
					"Request to GitHub user endpoint failed, retrying in 10 seconds...",
				),
			)
		}
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(10 * time.Second):
		}
	}
	err = log.WrapUser(
		lastError,
		EGitHubUserRequestFailed,
		"Timeout while trying to fetch your identity from GitHub.",
		"Timeout while trying fetch user identity from GitHub.",
	)
	g.logger.Debug(err)
	return map[string]string{}, err
}

func (g *gitHubFlow) getAPIClient(token string, basicAuth bool) (http.Client, error) {
	headers := map[string][]string{}
	if basicAuth {
		headers["authorization"] = []string{
			fmt.Sprintf("basic %s", base64.StdEncoding.EncodeToString(
				[]byte(fmt.Sprintf(
					"%s:%s",
					g.clientID,
					g.clientSecret,
				)),
			)),
		}
	} else if token != "" {
		headers["authorization"] = []string{
			fmt.Sprintf("bearer %s", token),
		}
	}
	apiClient, err := http.NewClientWithHeaders(g.apiClientConfig, g.logger, headers, true)
	if err != nil {
		return nil, log.WrapUser(
			err,
			EGitHubHTTPClientCreateFailed,
			"Authentication currently unavailable.",
			"Cannot create GitHub device flow authenticator because the HTTP client configuration failed.",
		)
	}
	return apiClient, nil
}

func (g *gitHubFlow) Deauthorize(ctx context.Context) {
	if g.accessToken == "" {
		return
	}
loop:
	for {
		req := &gitHubDeleteAccessTokenRequest{
			AccessToken: g.accessToken,
		}
		apiClient, err := g.getAPIClient(g.accessToken, true)
		if err != nil {
			g.logger.Warning(log.Wrap(err, EGitHubDeleteAccessTokenFailed, "Failed to delete access token"))
			return
		}
		statusCode, err := apiClient.Delete(
			fmt.Sprintf("/applications/%s/token", g.clientID),
			req,
			nil,
		)
		if err == nil && statusCode == 204 {
			g.accessToken = ""
			return
		}
		if err != nil {
			g.logger.Debug(
				log.Wrap(
					err,
					EGitHubDeleteAccessTokenFailed,
					"Failed to delete access token.",
				),
			)
		} else {
			g.logger.Debug(
				log.NewMessage(
					EGitHubDeleteAccessTokenFailed,
					"Failed to delete access token, invalid status code: %d",
					statusCode,
				),
			)
		}
		select {
		case <-time.After(10 * time.Second):
		case <-ctx.Done():
			break loop
		}
	}

}

//endregion

//region gitHubAuthorizationCodeFlow

type gitHubAuthorizationCodeFlow struct {
	gitHubFlow
}

func (g *gitHubAuthorizationCodeFlow) GetAuthorizationURL(_ context.Context) (string, error) {
	var link = &url.URL{}
	*link = *g.provider.url
	link.Path = "/login/oauth/authorize"
	query := link.Query()
	query.Set("client_id", g.provider.clientID)
	query.Set("login", g.username)
	query.Set("scope", g.provider.getScope())
	query.Set("state", g.connectionID)
	link.RawQuery = query.Encode()
	return link.String(), nil
}

func (g *gitHubAuthorizationCodeFlow) Verify(ctx context.Context, state string, authorizationCode string) (
	map[string]string,
	error,
) {
	if state != g.connectionID {
		return nil, log.UserMessage(
			EGitHubStateDoesNotMatch,
			"The returned code is invalid.",
			"The user provided a code that contained an invalid state component.",
		)
	}
	accessToken, err := g.getAccessToken(ctx, authorizationCode)
	g.accessToken = accessToken
	if err != nil {
		if accessToken != "" {
			g.Deauthorize(ctx)
		}
		return nil, err
	}
	return g.getIdentity(ctx, g.username, accessToken)
}

func (g *gitHubAuthorizationCodeFlow) getAccessToken(ctx context.Context, code string) (string, error) {
	var statusCode int
	var lastError error
loop:
	for {
		req := &gitHubAccessTokenRequest{
			ClientID:     g.provider.clientID,
			ClientSecret: g.provider.clientSecret,
			Code:         code,
			State:        g.connectionID,
		}
		resp := &gitHubAccessTokenResponse{}
		statusCode, lastError = g.client.Post("/login/oauth/access_token", req, resp)
		if statusCode != 200 {
			lastError = log.UserMessage(
				EGitHubAccessTokenFetchFailed,
				"Cannot authenticate at this time.",
				"Non-200 status code from GitHub access token API (%d; %s; %s).",
				statusCode,
				resp.Error,
				resp.ErrorDescription,
			)
		} else if lastError == nil {
			return resp.AccessToken, g.checkGrantedScopes(resp.Scope)
		}
		g.logger.Debug(lastError)
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(10 * time.Second):
		}
	}
	err := log.WrapUser(
		lastError,
		EGitHubTimeout,
		"Timeout while trying to obtain GitHub authentication data.",
		"Timeout while trying to obtain GitHub authentication data.",
	)
	g.logger.Debug(err)
	return "", err
}

//endregion

//region gitHubDeviceFlow

type gitHubDeviceFlow struct {
	gitHubFlow

	interval   time.Duration
	deviceCode string
}

func (d *gitHubDeviceFlow) GetAuthorizationURL(ctx context.Context) (
	verificationLink string,
	userCode string,
	expiresIn time.Duration,
	err error,
) {
	req := &gitHubDeviceRequest{
		ClientID: d.provider.clientID,
		Scope:    d.provider.getScope(),
	}
	var lastError error
	var statusCode int
loop:
	for {
		resp := &gitHubDeviceResponse{}
		statusCode, lastError = d.client.Post("/login/device/code", req, resp)
		if lastError == nil {
			if statusCode == 200 {
				d.interval = time.Duration(resp.Interval) * time.Second
				d.deviceCode = resp.DeviceCode
				return resp.VerificationURI, resp.UserCode, time.Duration(resp.ExpiresIn) * time.Second, nil
			} else {
				switch resp.Error {
				case "slow_down":
					// Let's assume this means that we reached the 50/hr limit. This is currently undocumented.
					lastError = log.UserMessage(
						EGitHubDeviceAuthorizationLimit,
						"Cannot authenticate at this time.",
						"GitHub device authorization limit reached (%s).",
						resp.ErrorDescription,
					)
					d.logger.Debug(lastError)
					return "", "", 0, lastError
				}
			}
			lastError = log.UserMessage(
				EGitHubDeviceCodeRequestFailed,
				"Cannot authenticate at this time.",
				"Non-200 status code from GitHub device code API (%d; %s; %s).",
				statusCode,
				resp.Error,
				resp.ErrorDescription,
			)
			d.logger.Debug(lastError)
		}
		d.logger.Debug(lastError)
		select {
		case <-time.After(10 * time.Second):
			continue
		case <-ctx.Done():
			break loop
		}
	}
	err = log.WrapUser(
		lastError,
		EGitHubTimeout,
		"Cannot authenticate at this time.",
		"Timeout while trying to obtain a GitHub device code.",
	)
	d.logger.Debug(err)
	return "", "", 0, err
}

func (d *gitHubDeviceFlow) Verify(ctx context.Context) (map[string]string, error) {
	accessToken, err := d.getAccessToken(ctx)
	d.accessToken = accessToken
	if err != nil {
		if accessToken != "" {
			d.Deauthorize(ctx)
		}
		return nil, err
	}
	return d.getIdentity(ctx, d.username, accessToken)
}

func (d *gitHubDeviceFlow) getAccessToken(ctx context.Context) (string, error) {
	var statusCode int
	var lastError error
loop:
	for {
		req := &gitHubAccessTokenRequest{
			ClientID:   d.provider.clientID,
			DeviceCode: d.deviceCode,
			GrantType:  "urn:ietf:params:oauth:grant-type:device_code",
		}
		resp := &gitHubAccessTokenResponse{}
		statusCode, lastError = d.client.Post("/login/oauth/access_token", req, resp)
		if statusCode != 200 {
			if resp.Error == "authorization_pending" {
				lastError = log.NewMessage(
					EGitHubAuthorizationPending,
					"User authorization still pending, retrying in %d seconds.",
					d.interval,
				)
			} else {
				lastError = log.UserMessage(
					EGitHubAccessTokenFetchFailed,
					"Cannot authenticate at this time.",
					"Non-200 status code from GitHub access token API (%d; %s; %s).",
					statusCode,
					resp.Error,
					resp.ErrorDescription,
				)
			}
		} else if lastError == nil {
			switch resp.Error {
			case "authorization_pending":
				lastError = log.UserMessage(EGitHubAuthorizationPending, "Authentication is still pending.", "The user hasn't completed the authentication process.")
			case "slow_down":
				if resp.Interval > 15 {
					// Assume we have exceeded the hourly rate limit, let's fall back.
					return "", log.UserMessage(EDeviceFlowRateLimitExceeded, "Cannot authenticate at this time. Please try again later.", "Rate limit for device flow exceeded, attempting authorization code flow.")
				}
			case "expired_token":
				return "", fmt.Errorf("BUG: expired token during device flow authentication")
			case "unsupported_grant_type":
				return "", fmt.Errorf("BUG: unsupported grant type error while trying device authorization")
			case "incorrect_client_credentials":
				// User entered the incorrect device code
				return "", log.UserMessage(EIncorrectClientCredentials, "GitHub authentication failed", "User entered incorrect device code")
			case "incorrect_device_code":
				// User entered the incorrect device code
				return "", log.UserMessage(EAuthFailed, "GitHub authentication failed", "User entered incorrect device code")
			case "access_denied":
				// User hit don't authorize
				return "", log.UserMessage(EAuthFailed, "GitHub authentication failed", "User canceled GitHub authentication")
			case "":
				return resp.AccessToken, d.checkGrantedScopes(resp.Scope)
			}
		}
		d.logger.Debug(lastError)
		select {
		case <-ctx.Done():
			break loop
		case <-time.After(d.interval):
		}
	}
	err := log.WrapUser(
		lastError,
		EGitHubTimeout,
		"Timeout while trying to obtain GitHub authentication data.",
		"Timeout while trying to obtain GitHub authentication data.",
	)
	d.logger.Debug(err)
	return "", err
}

type gitHubDeviceRequest struct {
	ClientID string `schema:"client_id"`
	Scope    string `schema:"scope"`
}

type gitHubDeviceResponse struct {
	DeviceCode       string `json:"device_code"`
	UserCode         string `json:"user_code"`
	VerificationURI  string `json:"verification_uri"`
	ExpiresIn        uint   `json:"expires_in" yaml:"expires_in"`
	Interval         uint   `json:"interval" yaml:"interval"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

//endregion
