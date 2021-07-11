package auth

import (
	"fmt"
	"os"
	"path"
	"time"

	"github.com/containerssh/http"
)

// ClientConfig is the configuration of the authentication client.
type ClientConfig struct {
	// Method is the authentication method in use.
	Method Method `json:"method" yaml:"method" default:"webhook"`

	// Webhook is the configuration for webhook authentication that calls out to an external HTTP server.
	Webhook WebhookClientConfig `json:"webhook" yaml:"webhook"`

	// OAuth2 is the configuration for OAuth2 authentication via Keyboard-Interactive.
	OAuth2  OAuth2ClientConfig `json:"oauth2" yaml:"oauth2"`

	// AuthTimeout is the timeout for the overall authentication call (e.g. verifying a password). If the server
	// responds with a non-200 response the call will be retried until this timeout is reached. This timeout
	// should be increased to ~180s for OAuth2 login.
	AuthTimeout time.Duration `json:"authTimeout" yaml:"authTimeout" default:"60s"`

	// Deprecated: use the configuration in Webhook instead.
	http.ClientConfiguration `json:",inline" yaml:",inline"`

	// Password is a flag to enable password authentication.
	// Deprecated: use the configuration in Webhook instead.
	Password bool `json:"password" yaml:"password" comment:"Perform password authentication" default:"true"`
	// PubKey is a flag to enable public key authentication.
	// Deprecated: use the configuration in Webhook instead.
	PubKey bool `json:"pubkey" yaml:"pubkey" comment:"Perform public key authentication" default:"true"`
}

func (c *ClientConfig) Validate() error {
	if err := c.Method.Validate(); err != nil {
		return fmt.Errorf("invalid method (%w)", err)
	}

	if c.Method == MethodWebhook && c.URL != "" {
		//goland:noinspection GoDeprecation
		if c.Webhook.URL != "" {
			return fmt.Errorf("both auth.url and auth.webhook.url are set")
		}
		//goland:noinspection GoDeprecation
		if err := c.ClientConfiguration.Validate(); err != nil {
			return fmt.Errorf("invalid client configuration (%w)", err)
		}
		//goland:noinspection GoDeprecation
		c.Webhook.realClientConfiguration = c.ClientConfiguration
	}
	var err error
	switch c.Method {
	case MethodWebhook:
		err = c.Webhook.Validate()
	case MethodOAuth2:
		err = c.OAuth2.Validate()
	default:
		return fmt.Errorf("invalid method: %s", c.Method)
	}

	if err != nil {
		return fmt.Errorf("invalid %s client configuration (%w)", c.Method, err)
	}

	return nil
}

type Method string

// Validate checks if the provided method is valid or not.
func (m Method) Validate() error {
	if m == "webhook" || m == "oauth2" {
		return nil
	}
	return fmt.Errorf("invalid value for method: %s", m)
}

// MethodWebhook authenticates using HTTP.
const MethodWebhook Method = "webhook"
// MethodOAuth2 authenticates by sending the user to a web interface using the keyboard-interactive facility.
const MethodOAuth2 Method = "oauth2"

// WebhookClientConfig is the configuration for webhook authentication.
type WebhookClientConfig struct {
	http.ClientConfiguration `json:",inline" yaml:",inline"`

	// Password is a flag to enable password authentication.
	Password bool `json:"password" yaml:"password" comment:"Perform password authentication" default:"true"`
	// PubKey is a flag to enable public key authentication.
	PubKey bool `json:"pubkey" yaml:"pubkey" comment:"Perform public key authentication" default:"true"`

	realClientConfiguration http.ClientConfiguration `json:"-" yaml:"-"`
}

// Validate validates the authentication client configuration.
func (c *WebhookClientConfig) Validate() error {
	if c.Timeout < 100*time.Millisecond {
		return fmt.Errorf("auth timeout value %s is too low, must be at least 100ms", c.Timeout.String())
	}
	if c.realClientConfiguration.URL == "" {
		if err := c.ClientConfiguration.Validate(); err != nil {
			return err
		}
		c.realClientConfiguration = c.ClientConfiguration
	}
	return nil
}

// OAuth2ClientConfig is the configuration for OAuth2-based authentication.
type OAuth2ClientConfig struct {
	// Redirect is the configuration for the redirect URI server.
	Redirect OAuth2RedirectConfig `json:"redirect" yaml:"redirect"`

	// ClientID is the public identifier for the ContainerSSH installation.
	ClientID string `json:"clientId" yaml:"clientId"`
	// ClientSecret is the OAuth2 secret value needed to obtain the access token.
	ClientSecret string `json:"clientSecret" yaml:"clientSecret"`

	// Provider is the provider to use for authentication
	Provider OAuth2ProviderName `json:"provider" yaml:"provider"`

	// GitHub is the configuration for the GitHub provider.
	GitHub GitHubConfig `json:"github" yaml:"github"`

	// OIDC is the configuration for the OpenID Connect provider.
	OIDC OIDCConfig `json:"oidc" yaml:"oidc"`

	// QRCodeClients contains a list of strings that are used to identify SSH clients that can display an ASCII QR Code
	// for the device authorization flow. Each string is compiled as regular expressions and are used to match against
	// the client version string.
	//
	// This is done primarily because OpenSSH cuts off the sent text and mangles the drawing characters, so it cannot
	// be used to display a QR code.
	QRCodeClients []string `json:"qrCodeClients" yaml:"qrCodeClients"`

	// DeviceFlowClients is a list of clients that can use the device flow without sending keyboard-interactive
	// questions.
	DeviceFlowClients []string `json:"deviceFlowClients" yaml:"deviceFlowClients"`
}

// Validate validates if the OAuth2 client configuration is valid.
func (o *OAuth2ClientConfig) Validate() error {
	if err := o.Redirect.Validate(); err != nil {
		return fmt.Errorf("invalid redirect configuration (%w)", err)
	}
	if o.ClientID == "" {
		return fmt.Errorf("empty client ID")
	}

	if o.ClientSecret == "" {
		return fmt.Errorf("empty client secret")
	}

	if err := o.Provider.Validate(); err != nil {
		return err
	}

	switch o.Provider {
	case OAuth2GitHubProvider:
		if err := o.GitHub.Validate(); err != nil {
			return fmt.Errorf("invalid GitHub configuration (%w)", err)
		}
	case OAuth2OIDCProvider:
		if err := o.OIDC.Validate(); err != nil {
			return fmt.Errorf("invalid OIDC configuration (%w)", err)
		}
	}

	return nil
}

type OAuth2ProviderName string

const (
	OAuth2GitHubProvider OAuth2ProviderName = "github"
	OAuth2OIDCProvider OAuth2ProviderName = "oidc"
)

func (o OAuth2ProviderName) Validate() error {
	switch o {
	case OAuth2GitHubProvider:
		return nil
	case OAuth2OIDCProvider:
		return nil
	default:
		return fmt.Errorf("invalid Oauth2 provider")
	}
}

// OAuth2RedirectConfig is the configuration for the HTTP server that serves the page presented to the user after they
// are authenticated.
type OAuth2RedirectConfig struct {
	http.ServerConfiguration `json:",inline" yaml:",inline"`

	// Webroot is a directory which contains all files that should be served as part of the return page
	// the user lands on when completing the OAuth2 authentication process. The webroot must contain an
	// index.html file, which will be served on the root URL. The files are read for each request and are not cached. If
	// the webroot is left empty the default ContainerSSH return page is presented.
	Webroot string `json:"webroot" yaml:"webroot"`
}

// Validate checks if the redirect server configuration is valid. Particularly, it checks the HTTP server
// parameters as well as if the webroot is valid and contains an index.html.
func (o OAuth2RedirectConfig) Validate() error {
	if err := o.ServerConfiguration.Validate(); err != nil {
		return err
	}
	if o.Webroot != "" {
		webrootStat, err := os.Stat(o.Webroot)
		if err != nil {
			return fmt.Errorf("invalid webroot (%w)", err)
		}
		if !webrootStat.IsDir() {
			return fmt.Errorf("invalid webroot (not a directory)")
		}
		indexStat, err := os.Stat(path.Join(o.Webroot, "index.html"))
		if err != nil {
			return fmt.Errorf("webroot does not contain an index.html file (%w)", err)
		}
		if indexStat.IsDir() {
			return fmt.Errorf("webroot does not contain an index.html file (index.html is a directory)")
		}
	}
	return nil
}