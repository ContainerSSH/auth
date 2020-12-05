package auth

import (
	"net"
)

// Client is an authentication client that provides authentication methods. Each authentication method returns a bool
// if the authentication was successful, and an error if the authentication failed due to a connection error.
type Client interface {
	// Password authenticates with a password from the client. It returns a bool if the authentication as successful
	// or not. If an error happened while contacting the authentication server it will return an error.
	Password(
		username string,
		password []byte,
		connectionID string,
		remoteAddr net.IP,
	) (bool, error)

	// PubKey authenticates with a public key from the client. It returns a bool if the authentication as successful
	// or not. If an error happened while contacting the authentication server it will return an error.
	PubKey(
		username string,
		pubKey string,
		connectionID string,
		remoteAddr net.IP,
	) (bool, error)
}
