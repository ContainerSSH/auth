package auth

// PasswordAuthRequest is an authentication request for password authentication.
//
// swagger:model PasswordAuthRequest
type PasswordAuthRequest struct {
	// Username is the username provided for authentication.
	//
	// required: true
	Username string `json:"username"`

	// RemoteAddress is the IP address of the user trying to authenticate.
	//
	// required: true
	RemoteAddress string `json:"remoteAddress"`

	// SessionID is an opaque ID to identify the SSH session in question.
	//
	// required: true
	SessionID string `json:"sessionId"`

	// Password the user provided for authentication.
	//
	// required: true
	Password []byte `json:"passwordBase64"`
}

// PublicKeyAuthRequest is an authentication request for public key authentication.
//
// swagger:model PublicKeyAuthRequest
type PublicKeyAuthRequest struct {
	// Username is the username provided for authentication.
	//
	// required: true
	Username string `json:"username"`

	// RemoteAddress is the IP address of the user trying to authenticate.
	//
	// required: true
	RemoteAddress string `json:"remoteAddress"`

	// SessionID is an opaque ID to identify the SSH session in question.
	//
	// required: true
	SessionID string `json:"sessionId"`

	// PublicKey is a serialized key data in SSH wire format.
	//
	// required: true
	PublicKey []byte `json:"publicKeyBase64"`
}

// ResponseBody is a response to authentication requests.
//
// swagger:model AuthResponseBody
type ResponseBody struct {
	// Success indicates if the authentication was successful.
	//
	// required: true
	Success bool `json:"success"`
}

// Response is the full HTTP authentication response.
//
// swagger:response AuthResponse
type Response struct {
	// The response body
	//
	// in: body
	Body ResponseBody
}
