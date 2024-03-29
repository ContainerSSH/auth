package auth

import (
	goHttp "net/http"
	"strings"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
)

type handler struct {
	passwordHandler goHttp.Handler
	pubkeyHandler   goHttp.Handler
}

func (h handler) ServeHTTP(writer goHttp.ResponseWriter, request *goHttp.Request) {
	parts := strings.Split(request.URL.Path, "/")
	switch parts[len(parts)-1] {
	case "password":
		h.passwordHandler.ServeHTTP(writer, request)
	case "pubkey":
		h.pubkeyHandler.ServeHTTP(writer, request)
	default:
		writer.WriteHeader(404)
	}
}

type passwordHandler struct {
	backend Handler
	logger  log.Logger
}

func (p *passwordHandler) OnRequest(request http.ServerRequest, response http.ServerResponse) error {
	requestObject := PasswordAuthRequest{}
	if err := request.Decode(&requestObject); err != nil {
		return err
	}
	success, err := p.backend.OnPassword(
		requestObject.Username,
		requestObject.Password,
		requestObject.RemoteAddress,
		requestObject.ConnectionID,
	)
	if err != nil {
		p.logger.Debug(log.Wrap(err, ERequestDecodeFailed, "failed to execute password request"))
		response.SetStatus(500)
		response.SetBody(ResponseBody{
			Success: false,
		})
		return nil
	} else {
		response.SetBody(ResponseBody{
			Success: success,
		})
	}
	return nil
}

type pubKeyHandler struct {
	backend Handler
	logger  log.Logger
}

func (p *pubKeyHandler) OnRequest(request http.ServerRequest, response http.ServerResponse) error {
	requestObject := PublicKeyAuthRequest{}
	if err := request.Decode(&requestObject); err != nil {
		return err
	}
	success, err := p.backend.OnPubKey(
		requestObject.Username,
		requestObject.PublicKey,
		requestObject.RemoteAddress,
		requestObject.ConnectionID,
	)
	if err != nil {
		p.logger.Debug(log.Wrap(err, ERequestDecodeFailed, "failed to execute public key request"))
		response.SetStatus(500)
		response.SetBody(ResponseBody{
			Success: false,
		})
		return nil
	} else {
		response.SetBody(ResponseBody{
			Success: success,
		})
	}
	return nil
}
