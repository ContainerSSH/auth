package auth

type Handler interface {
	// OnPassword is called if the client requests a password authentication.
	//
	// - Username is the username the user entered.
	// - RemoteAddress is the IP address of the user.
	// - SessionID is an opaque identifier for the current session.
	// - Password is the password the user entered.
	//
	// The method must return a boolean if the authentication was successful, and an error if the authentication failed
	// for other reasons (e.g. backend database was not available). If an error is returned the server responds with
	// a HTTP 500 response.
	OnPassword(
		Username string,
		RemoteAddress string,
		SessionID string,
		Password []byte,
	) (bool, error)

	// OnPubKey is called when the client requests a public key authentication.
	//
	// - Username is the username the user entered.
	// - RemoteAddress is the IP address of the user.
	// - SessionID is an opaque identifier for the current session.
	// - PublicKey is the public key of the user in OpenSSH wire format.
	//
	// The method must return a boolean if the authentication was successful, and an error if the authentication failed
	// for other reasons (e.g. backend database was not available). If an error is returned the server responds with
	// a HTTP 500 response.
	OnPubKey(
		Username string,
		RemoteAddress string,
		SessionID string,
		PublicKey []byte,
	) (bool, error)
}
