[![ContainerSSH - Launch Containers on Demand](https://containerssh.github.io/images/logo-for-embedding.svg)](https://containerssh.github.io/)

<!--suppress HtmlDeprecatedAttribute -->
<h1 align="center">ContainerSSH Authentication Library</h1>

[![Go Report Card](https://goreportcard.com/badge/github.com/containerssh/auth?style=for-the-badge)](https://goreportcard.com/report/github.com/containerssh/auth)
[![LGTM Alerts](https://img.shields.io/lgtm/alerts/github/ContainerSSH/auth?style=for-the-badge)](https://lgtm.com/projects/g/ContainerSSH/auth/)

This library provides the server and client components for the [authentication webhook](https://containerssh.github.io/getting-started/authserver/)

<p align="center"><strong>Note: This is a developer documentation.</strong><br />The user documentation for ContainerSSH is located at <a href="https://containerssh.github.io">containerssh.github.io</a>.</p>

## Creating a server

As a core component for your authentication server you will have to implement the [`Handler` interface](handler.go):

```go
type myHandler struct {
}

func (h *myHandler) OnPassword(
    Username string,
    RemoteAddress string,
    ConnectionID string,
    Password []byte,
) (bool, error) {
    if Username == "foo" && string(Password) == "bar" {
        return true, nil
    }
    if Username == "crash" {
        // Simulate a database failure
        return false, fmt.Errorf("database error")
    }
    return false, nil
}
```

Then you can use this handler to create a simple web server using the
[http library](https://github.com/containerssh/http). You can create the server as follows:

```go
server := auth.NewServer(
    http.ServerConfiguration{
        Listen: "127.0.0.1:8080",
    },
    &myHandler{},
    logger,
    func() {
        // This function will be called when the server is ready.
    	// You can pass nil here.
    }
)

go func() {
    if err := server.Run(); err != nil {
        // Handle error
    }
}

// When done, shut down server with an optional context for the shutdown deadline
server.Shutdown(context.Background())
```

The `logger` is a logger from the [github.com/containerssh/log](http://github.com/containerssh/log) package. The server
configuration optionally allows you to configure mutual TLS authentication.
[See the documentation for details.](https://github.com/containerssh/http)

You can also use the authentication handler with the native Go HTTP library:

```go
func main() {
    logger := standard.New()
    httpHandler := auth.NewHandler(&myHandler{}, logger)
    http.HandleFunc("/auth", httpHandler)
    http.ListenAndServe(":8090", nil)
}
```

## Creating a client

This library also provides a HTTP client for authentication servers. This library can be used as follows:

```go
client := auth.NewHttpAuthClient(
    auth.ClientConfig{
        Url: "http://localhost:8080"
        Password: true,
        PubKey: false,
    },
    logger,
)

success, err := client.Password(
    "foo",
    []byte("bar"),
    "0123456789ABCDEF",
    ip
) (bool, error)

success, err := client.PubKey(
    "foo",
    "ssh-rsa ...",
    "0123456789ABCDEF",
    ip
) (bool, error)
```