# Message / error codes

| Code | Explanation |
|------|-------------|
| `AUTH` | ContainerSSH is trying to contact the authentication backend to verify the user credentials. |
| `AUTH_AVAILABLE` | The ContainerSSH authentication server is now available. |
| `AUTH_BACKEND_ERROR` | The ContainerSSH authentication server responded with a non-200 status code. ContainerSSH will retry the authentication for a few times before giving up. This is most likely a bug in your authentication server, please check your logs. |
| `AUTH_DISABLED` | The authentication method the client tried is disabled. |
| `AUTH_FAILED` | The user has provided invalid credentials and the authentication is rejected. |
| `AUTH_INVALID_STATUS` | This message indicates that the authentication server returned an invalid HTTP status code. |
| `AUTH_SERVER_DECODE_FAILED` | The ContainerSSH Auth library failed to decode a request from ContainerSSH. |
| `AUTH_SUCCESSFUL` | The user has provided the correct credentials and the authentication is accepted. |

