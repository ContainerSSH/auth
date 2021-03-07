package auth

// This message indicates that the authentication server returned an invalid HTTP status code.
const EInvalidStatus = "AUTH_INVALID_STATUS"

// ContainerSSH is trying to contact the authentication backend to verify the user credentials.
const MAuth = "AUTH"

// The ContainerSSH authentication server responded with a non-200 status code. ContainerSSH will retry the
// authentication for a few times before giving up. This is most likely a bug in your authentication server, please
// check your logs.
const EAuthBackendError = "AUTH_BACKEND_ERROR"

// The user has provided invalid credentials and the authentication is rejected.
const EAuthFailed = "AUTH_FAILED"

// The user has provided the correct credentials and the authentication is accepted.
const MAuthSuccessful = "AUTH_SUCCESSFUL"
