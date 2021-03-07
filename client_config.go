package auth

import (
	"fmt"
	"time"

	"github.com/containerssh/http"
)

// ClientConfig is the configuration of the authentication client.
type ClientConfig struct {
	http.ClientConfiguration `json:",inline" yaml:",inline"`

	// AuthTimeout is the timeout for the overall authentication call (e.g. verifying a password). If the server
	// responds with a non-200 response the call will be retried until this timeout is reached.
	AuthTimeout time.Duration `json:"authTimeout" yaml:"authTimeout" default:"60s"`

	// Password is a flag to enable password authentication.
	Password bool `json:"password" yaml:"password" comment:"Perform password authentication" default:"true"`
	// PubKey is a flag to enable public key authentication.
	PubKey bool `json:"pubkey" yaml:"pubkey" comment:"Perform public key authentication" default:"false"`
}

// Validate validates the authentication client configuration.
func (c *ClientConfig) Validate() error {
	if c.Timeout < 100*time.Millisecond {
		return fmt.Errorf("auth timeout value %s is too low, must be at least 100ms", c.Timeout.String())
	}
	return c.ClientConfiguration.Validate()
}
