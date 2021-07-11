package auth_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	goHttp "net/http"
	"strings"
	"time"

	"github.com/containerssh/http"
	"github.com/containerssh/log"
	"github.com/containerssh/service"
	"github.com/gorilla/mux"
)

func newGitHubSimulator(
	clientID string,
	clientSecret string,
	logger log.Logger,
	onReady func(string),
) service.Service {
	h := &gitHubSimulatorHandler{
		clientID:     clientID,
		clientSecret: clientSecret,
		tokens:       map[string]gitHubSimulatorToken{},
	}
	m := mux.NewRouter()
	m.HandleFunc("/login/device", h.device)
	m.HandleFunc("/login/oauth/authorize", h.authorize)
	m.HandleFunc("/login/oauth/access_token", h.accessToken)
	m.HandleFunc("/user", h.user)
	m.HandleFunc("/applications/{clientId}/token", h.token)
	srv, err := http.NewServer(
		"github", http.ServerConfiguration{
			Listen: "127.0.0.1:8081",
		}, m, logger, onReady,
	)
	if err != nil {
		panic(err)
	}
	return srv
}

type gitHubSimulatorToken struct {
	ID             int                 `json:"id"`
	URL            string              `json:"url"`
	Scopes         []string            `json:"scopes"`
	Token          string              `json:"token"`
	TokenLastEight string              `json:"token_last_eight"`
	HashedToken    string              `json:"hashed_token"`
	App            gitHubSimulatorApp  `json:"app"`
	CreatedAt      time.Time           `json:"created_at"`
	UpdatedAt      time.Time           `json:"updated_at"`
	Fingerprint    string              `json:"string"`
	User           gitHubSimulatorUser `json:"user"`
}

type gitHubSimulatorApp struct {
	URL      string `json:"url"`
	Name     string `json:"name"`
	ClientID string `json:"client_id"`
}

type gitHubSimulatorHandler struct {
	clientID     string
	clientSecret string
	tokens       map[string]gitHubSimulatorToken
}

type gitHubSimulatorUser struct {
	Login                   string `json:"login"`
	ID                      int    `json:"id"`
	NodeID                  string `json:"node_id"`
	Type                    string `json:"type"`
	AvatarURL               string `json:"avatar_url"`
	ProfileURL              string `json:"html_url"`
	Name                    string `json:"name"`
	Company                 string `json:"company"`
	BlogURL                 string `json:"blog"`
	Location                string `json:"location"`
	Email                   string `json:"email"`
	Bio                     string `json:"bio"`
	TwitterUsername         string `json:"twitter_username"`
	TwoFactorAuthentication *bool  `json:"two_factor_authentication,omitempty"`
}

func (g *gitHubSimulatorHandler) accessToken(writer goHttp.ResponseWriter, request *goHttp.Request) {

}

func (g *gitHubSimulatorHandler) authorize(writer goHttp.ResponseWriter, request *goHttp.Request) {

}

func (g *gitHubSimulatorHandler) user(writer goHttp.ResponseWriter, request *goHttp.Request) {

}

type gitHubSimulatorTokenRequest struct {
	AccessToken string `json:"access_token"`
}

func (g *gitHubSimulatorHandler) token(writer goHttp.ResponseWriter, request *goHttp.Request) {
	vars := mux.Vars(request)
	clientID := vars["clientId"]
	if clientID == "" {
		writer.WriteHeader(404)
		return
	}
	if clientID != g.clientID {
		writer.WriteHeader(403)
		return
	}
	if request.Method != "DELETE" {
		writer.WriteHeader(405)
		return
	}
	authorization := request.Header.Get("authorization")
	if authorization == "" || !strings.HasPrefix("basic ", authorization) {
		writer.WriteHeader(401)
		return
	}
	credentials, err := base64.StdEncoding.DecodeString(authorization[6:])
	if err != nil {
		_, _ = writer.Write([]byte(fmt.Sprintf("failed to decode authorization header (%v)", err)))
		writer.WriteHeader(401)
		return
	}
	parts := strings.SplitN(string(credentials), ":", 2)
	if len(parts) != 2 {
		writer.WriteHeader(401)
		return
	}
	if parts[0] != g.clientID || parts[1] != g.clientSecret {
		writer.WriteHeader(401)
		return
	}
	decoder := json.NewDecoder(request.Body)
	req := &gitHubSimulatorTokenRequest{}
	if err := decoder.Decode(req); err != nil {
		writer.WriteHeader(400)
		return
	}
	if _, ok := g.tokens[req.AccessToken]; !ok {
		writer.WriteHeader(404)
		return
	}
	delete(g.tokens, req.AccessToken)
	writer.WriteHeader(204)
}

func (g *gitHubSimulatorHandler) device(writer goHttp.ResponseWriter, request *goHttp.Request) {

}
