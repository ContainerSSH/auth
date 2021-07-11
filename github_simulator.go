package auth

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

// GitHubSimulatorScopesCallback is a function that is called during the login process when scopes are requested.
// The function can determine what scopes to grant out of those requested.
type GitHubSimulatorScopesCallback func(scopesRequested []string) (scopesGranted []string)

// GitHubSimulator is a partial simulation of the GitHub API for implementing the OAuth2 parts required by ContainerSSH
// to operate.
type GitHubSimulator interface {
	service.Service

	// AddClient creates a new client ID and secret.
	AddClient(name string) (clientID string, clientSecret string)

	// AddUser adds a user to the simulator. The only thing we need here is a username, since we'll let every user
	// authenticate automatically.
	AddUser(
		login string,
		avatarURL string,
		profileURL string,
		name string,
		company string,
		blogURL string,
		location string,
		email string,
		bio string,
		twitterUsername string,
		twoFactorAuthentication bool,
	)

	// AddOrg creates an organization for the purposes of an organization membership check.
	AddOrg(
		login string,
	)

	// AddMember adds a user to an organization. This is useful for the organization membership check.
	AddMember(
		org string,
		user string,
	)

	// PerformDeviceLogin performs a device login flow using a code. The first parameter is the device code from the
	// login session, while the second parameter is a callback to determine which scopes to grant. The second parameter
	// can be used to simulate situations where the user doesn't grant sufficient permissions.
	PerformDeviceLogin(code string, username string, scopesCallback GitHubSimulatorScopesCallback)

	// PerformRedirectLogin simulates a browser-based login. On the return website it will look for an HTML element with
	// the ID "code" and extract its contents as the return code. Since the simulation does not involve a true browser
	// advanced features such as JavaScript are not supported.
	PerformRedirectLogin(link string, username string, scopesCallback GitHubSimulatorScopesCallback) (string, error)
}

// NewGitHubSimulator creates a small webserver that can be used to simulate GitHub OAuth behavior.
func NewGitHubSimulator(
	logger log.Logger,
	onReady func(string),
) GitHubSimulator {
	h := &gitHubSimulatorHandler{
		apps:        []*gitHubSimulatorApp{},
		users:       map[string]*gitHubSimulatorUser{},
		orgs:        map[string]*gitHubSimulatorOrg{},
		memberships: map[string][]string{},
		tokens:      map[string]*gitHubSimulatorToken{},
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
	return &githubSimulator{
		srv,
		h,
	}
}

type githubSimulator struct {
	http.Server
	handler *gitHubSimulatorHandler
}

func (g *githubSimulator) AddClient(name string) (clientID string, clientSecret string) {
	app := &gitHubSimulatorApp{
		URL:      "http://localhost",
		Name:     name,
		ClientID: generateRandomID(5),
		clientSecret: generateRandomID(5),
	}
	g.handler.apps = append(g.handler.apps, app)
	return app.ClientID, app.clientSecret
}

func (g githubSimulator) AddUser(
	login string,
	avatarURL string,
	profileURL string,
	name string,
	company string,
	blogURL string,
	location string,
	email string,
	bio string,
	twitterUsername string,
	twoFactorAuthentication bool,
) {
	panic("implement me")
}

func (g githubSimulator) AddOrg(login string) {
	panic("implement me")
}

func (g githubSimulator) AddMember(org string, user string) {
	panic("implement me")
}

func (g githubSimulator) PerformDeviceLogin(
	code string,
	username string,
	scopesCallback GitHubSimulatorScopesCallback,
) {
	panic("implement me")
}

func (g githubSimulator) PerformRedirectLogin(
	link string,
	username string,
	scopesCallback GitHubSimulatorScopesCallback,
) (string, error) {
	panic("implement me")
}

type gitHubSimulatorHandler struct {
	tokens      map[string]*gitHubSimulatorToken
	users       map[string]*gitHubSimulatorUser
	orgs        map[string]*gitHubSimulatorOrg
	memberships map[string][]string
	apps        []*gitHubSimulatorApp
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
	URL          string `json:"url"`
	Name         string `json:"name"`
	ClientID     string `json:"client_id"`
	clientSecret string
}

type gitHubSimulatorUser struct {
	Login                   string `json:"login"`
	ID                      int    `json:"id"`
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

type gitHubSimulatorOrg struct {
	Login string `json:"login"`
}

// accessToken simulates the behavior of the access token endpoint.
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
