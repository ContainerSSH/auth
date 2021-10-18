package auth_test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/containerssh/geoip"
	"github.com/containerssh/http"
	"github.com/containerssh/log"
	"github.com/containerssh/metrics"
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

func (h *handler) OnPubKey(Username string, PublicKey string, RemoteAddress string, ConnectionID string) (bool, error) {
	if RemoteAddress != "127.0.0.1" {
		return false, fmt.Errorf("invalid IP: %s", RemoteAddress)
	}
	if ConnectionID != "0123456789ABCDEF" {
		return false, fmt.Errorf("invalid connection ID: %s", ConnectionID)
	}
	if Username == "foo" && PublicKey == "ssh-rsa asdf" {
		return true, nil
	}
	if Username == "crash" {
		// Simulate a database failure
		return false, fmt.Errorf("database error")
	}
	return false, nil
}

func TestAuth(t *testing.T) {
	logger := log.NewTestLogger(t)
	logger.Info(
		log.NewMessage(
			"TEST",
			"FYI: errors during this test are expected as we test against error cases.",
		),
	)

	for name, subpath := range map[string]string{"empty": "", "auth": "/auth"} {
		t.Run(fmt.Sprintf("subpath_%s", name), func(t *testing.T) {
			client, lifecycle, metricsCollector, err := initializeAuth(logger, subpath)
			if err != nil {
				assert.Fail(t, "failed to initialize auth", err)
				return
			}
			defer lifecycle.Stop(context.Background())

			success, err := client.Password("foo", []byte("bar"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
			assert.Equal(t, nil, err)
			assert.Equal(t, true, success)
			assert.Equal(t, float64(1), metricsCollector.GetMetric(auth.MetricNameAuthBackendRequests)[0].Value)
			assert.Equal(t, float64(1), metricsCollector.GetMetric(auth.MetricNameAuthSuccess)[0].Value)

			success, err = client.Password("foo", []byte("baz"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
			assert.Equal(t, nil, err)
			assert.Equal(t, false, success)
			assert.Equal(t, float64(1), metricsCollector.GetMetric(auth.MetricNameAuthFailure)[0].Value)

			success, err = client.Password("crash", []byte("baz"), "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
			assert.NotEqual(t, nil, err)
			assert.Equal(t, false, success)
			assert.Equal(t, float64(1), metricsCollector.GetMetric(auth.MetricNameAuthBackendFailure)[0].Value)

			success, err = client.PubKey("foo", "ssh-rsa asdf", "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
			assert.Equal(t, nil, err)
			assert.Equal(t, true, success)

			success, err = client.PubKey("foo", "ssh-rsa asdx", "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
			assert.Equal(t, nil, err)
			assert.Equal(t, false, success)

			success, err = client.PubKey("crash", "ssh-rsa asdx", "0123456789ABCDEF", net.ParseIP("127.0.0.1"))
			assert.NotEqual(t, nil, err)
			assert.Equal(t, false, success)
		})
	}
}

func initializeAuth(logger log.Logger, subpath string) (auth.Client, service.Lifecycle, metrics.Collector, error) {
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
		return nil, nil, nil, err
	}

	geoipProvider, err := geoip.New(geoip.Config{
		Provider: geoip.DummyProvider,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	metricsCollector := metrics.New(geoipProvider)

	client, err := auth.NewHttpAuthClient(
		auth.ClientConfig{
			ClientConfiguration: http.ClientConfiguration{
				URL:     fmt.Sprintf("http://127.0.0.1:8080%s", subpath),
				Timeout: 2 * time.Second,
			},
			Password:    true,
			PubKey:      true,
			AuthTimeout: 2 * time.Second,
		},
		logger,
		metricsCollector,
	)
	if err != nil {
		return nil, nil, nil, err
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
	return client, lifecycle, metricsCollector, nil
}
