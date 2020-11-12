package auth

import (
	goHttp "net/http"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
)

type handler struct {
	passwordHandler goHttp.Handler
	pubkeyHandler   goHttp.Handler
}

func (h handler) ServeHTTP(writer goHttp.ResponseWriter, request *goHttp.Request) {
	switch request.URL.Path {
	case "/password":
		h.passwordHandler.ServeHTTP(writer, request)
	case "/pubkey":
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
		requestObject.SessionID,
	)
	if err != nil {
		p.logger.Warningf("failed to execute password request (%v)", err)
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
		requestObject.SessionID,
	)
	if err != nil {
		p.logger.Warningf("failed to execute public key request (%v)", err)
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
