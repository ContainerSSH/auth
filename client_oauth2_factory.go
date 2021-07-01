package auth

import (
	"fmt"
	goHttp "net/http"

	"github.com/containerssh/log"
	"github.com/containerssh/metrics"
	"github.com/containerssh/service"

	"github.com/containerssh/http"

	"github.com/containerssh/auth/v2/oauth2"
)

func NewOAuth2Client(config ClientConfig, logger log.Logger, collector metrics.Collector) (
	Client,
	service.Service,
	error,
) {
	var err error
	if config.Method != MethodOAuth2 {
		return nil, nil, fmt.Errorf("authentication is not set to oauth2")
	}
	if err := config.Validate(); err != nil {
		return nil, nil, err
	}

	var fs goHttp.FileSystem
	if config.OAuth2.Redirect.Webroot != "" {
		fs = goHttp.Dir(config.OAuth2.Redirect.Webroot)
	} else {
		fs = oauth2.GetFilesystem()
	}

	redirectServer, err := http.NewServer(
		"OAuth2 Redirect Server",
		config.OAuth2.Redirect.ServerConfiguration,
		goHttp.FileServer(fs),
		logger,
		func(url string) {
			logger.Info(log.NewMessage(EOAuth2Available, "OAuth2 redirect server is now available at %s", url))
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create redirect page server (%w)", err)
	}

	var provider OAuth2Provider
	switch config.OAuth2.Provider {
	case OAuth2GitHubProvider:
		provider, err = newGitHubProvider(config, logger)
	}

	return &oauth2Client{
		logger: logger,
		provider: provider,
	}, redirectServer, nil
}
