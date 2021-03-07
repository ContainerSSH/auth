# Message / error codes

| Code | Explanation |
|------|-------------|
| `AUTH` | ContainerSSH is trying to contact the authentication backend. |
| `AUTH_BACKEND_ERROR` | The ContainerSSH authentication server responded with a non-200 status code. ContainerSSH will retry the authentication for a few times before giving up. This is most likely a bug in your authentication server, please check your logs. |
| `AUTH_FAILED` | The user has provided invalid credentials and the authentication is rejected. |
| `AUTH_INVALID_STATUS` | This message indicates that the authentication server returned an invalid HTTP status code. |
| `AUTH_SUCCESSFUL` | The user has provided the correct credentials and the authentication is accepted. |

