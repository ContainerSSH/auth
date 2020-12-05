package auth_test

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/containerssh/http"
	"github.com/containerssh/log/standard"
	"github.com/containerssh/service"
	"github.com/stretchr/testify/assert"

	"github.com/containerssh/auth"
)

type handler struct {
}

func (h *handler) OnPassword(
	Username string,
	Password []byte,
	RemoteAddress string,
	ConnectionID string,
) (bool, error) {
	if RemoteAddress != "127.0.0.1" {
		return false, fmt.Errorf("invalid IP: %s", RemoteAddress)
	}
	if ConnectionID != "0123456789ABCDEF" {
		return false, fmt.Errorf("invalid connection ID: %s", ConnectionID)
	}
	if Username == "foo" && string(Password) == "bar" {
		return true, nil
	}
	if Username == "crash" {
		// Simulate a database failure
		return false, fmt.Errorf("database error")
	}
	return false, nil
}

func (h *handler) OnPubKey(Username string, PublicKey []byte, RemoteAddress string, ConnectionID string) (bool, error) {
	if RemoteAddress != "127.0.0.1" {
		return false, fmt.Errorf("invalid IP: %s", RemoteAddress)
	}
	if ConnectionID != "0123456789ABCDEF" {
		return false, fmt.Errorf("invalid session ID: %s", ConnectionID)
	}
	if Username == "foo" && bytes.Equal(PublicKey, []byte("ssh-rsa asdf")) {
		return true, nil
	}
	if Username == "crash" {
		// Simulate a database failure
		return false, fmt.Errorf("database error")
	}
	return false, nil
}

func TestAuth(t *testing.T) {
	client, lifecycle, err := initializeAuth()
	if err != nil {
		assert.Fail(t, "failed to initialize auth", err)
		return
	}
	defer lifecycle.Stop(context.Background())

	success, err := client.Password("foo", []byte("bar"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
	assert.Equal(t, nil, err)
	assert.Equal(t, true, success)

	success, err = client.Password("foo", []byte("baz"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
	assert.Equal(t, nil, err)
	assert.Equal(t, false, success)

	success, err = client.Password("crash", []byte("baz"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
	assert.NotEqual(t, nil, err)
	assert.Equal(t, false, success)

	success, err = client.PubKey("foo", []byte("ssh-rsa asdf"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
	assert.Equal(t, nil, err)
	assert.Equal(t, true, success)

	success, err = client.PubKey("foo", []byte("ssh-rsa asdx"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
	assert.Equal(t, nil, err)
	assert.Equal(t, false, success)

	success, err = client.PubKey("crash", []byte("ssh-rsa asdx"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
	assert.NotEqual(t, nil, err)
	assert.Equal(t, false, success)
}

func initializeAuth() (auth.Client, service.Lifecycle, error) {
	logger := standard.New()
	ready := make(chan bool, 1)
	errors := make(chan error)

	server, err := auth.NewServer(
		http.ServerConfiguration{
			Listen: "127.0.0.1:8080",
		},
		&handler{},
		logger,
	)
	if err != nil {
		return nil, nil, err
	}

	client, err := auth.NewHttpAuthClient(
		auth.ClientConfig{
			ClientConfiguration: http.ClientConfiguration{
				Url: "http://127.0.0.1:8080",
			},
			Password: true,
			PubKey:   true,
		},
		logger,
	)
	if err != nil {
		return nil, nil, err
	}

	lifecycle := service.NewLifecycle(server)
	lifecycle.OnRunning(
		func(_ service.Service, _ service.Lifecycle) {
			ready <- true
		},
	)

	go func() {
		if err := lifecycle.Run(); err != nil {
			errors <- err
		}
		close(errors)
	}()
	<-ready
	return client, lifecycle, nil
}