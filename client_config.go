package auth

import (
	"github.com/containerssh/http"
)

// ClientConfig is the configuration of the authentication client.
type ClientConfig struct {
	http.ClientConfiguration `json:",inline" yaml:",inline"`

	// Password is a flag to enable password authentication.
	Password bool `json:"password" yaml:"password" comment:"Perform password authentication" default:"true"`
	// PubKey is a flag to enable public key authentication.
	PubKey bool `json:"pubkey" yaml:"pubkey" comment:"Perform public key authentication" default:"false"`
}
