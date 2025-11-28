package services

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type AuthService interface {
	RedirectUrl() string
	CallbackEndpoint() string
	CallbackHandler(r *http.Request) (*UserInfo, error)
}

const (
	GithubAuthUrl         = "https://github.com/login/oauth/authorize"
	GithubAccessTokenUrl  = "https://github.com/login/oauth/access_token"
	GithubUserApiUrl      = "https://api.github.com/user"
	GIthubUserEmailApiUrl = "https://api.github.com/user/emails"
)

func generateGithubAuthUrl(clientId string, scopes []string) string {
	values := url.Values{}
	for _, scope := range scopes {
		values.Add("scope", scope)
	}
	values.Add("client_id", clientId)
	return fmt.Sprintf("%s?%s", GithubAuthUrl, values.Encode())
}
func generateGithubAccessToken(clientId, clientSecret, sessionCode string) string {
	values := url.Values{}
	values.Add("client_id", clientId)
	values.Add("client_secret", clientSecret)
	values.Add("code", sessionCode)
	return fmt.Sprintf("%s?%s", GithubAccessTokenUrl, values.Encode())
}

type GithubService struct {
	ClientSecret     string
	ClientId         string
	AuthResponsePath string
}

func (g *GithubService) RedirectUrl() string {
	return generateGithubAuthUrl(g.ClientId, []string{"user"})
}
func (g *GithubService) CallbackEndpoint() string {
	return g.AuthResponsePath
}

var ErrCannotFindEmail error = errors.New("unable to determine github email")

func (g *GithubService) CallbackHandler(r *http.Request) (*UserInfo, error) {
	code := r.URL.Query().Get("code")
	url := generateGithubAccessToken(g.ClientId, g.ClientSecret, code)
	token := struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := getWrapped(url, map[string]string{
		"Accept": "application/json",
	}, http.StatusOK, &token); err != nil {
		return nil, err
	}
	loginInfo := struct {
		Login string `json:"login"`
	}{}
	if err := fetchJsonAuthed(GithubUserApiUrl, token.AccessToken, &loginInfo); err != nil {
		return nil, err
	}
	emails := []struct {
		Email    string `json:"email,omitempty"`
		Verified bool   `json:"verified,omitempty"`
		Primary  bool   `json:"primary,omitempty"`
	}{}
	if err := fetchJsonAuthed(GIthubUserEmailApiUrl, token.AccessToken, &emails); err != nil {
		return nil, err
	}
	userEmail := ""
	for _, email := range emails {
		if email.Primary && email.Verified {
			userEmail = email.Email
			break
		}
	}
	if userEmail == "" {
		return nil, ErrCannotFindEmail
	}
	return &UserInfo{Username: loginInfo.Login, Email: userEmail}, nil
}

func fetchJsonAuthed(url string, accessToken string, v any) error {
	return getWrapped(url, map[string]string{"Authorization": fmt.Sprintf("Bearer %s", accessToken)}, http.StatusOK, v)
}

func getWrapped(url string, headers map[string]string, expected int, v any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	for k, v := range headers {
		req.Header.Add(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != expected {
		data, err := io.ReadAll(resp.Body)
		return errors.Join(err, fmt.Errorf("getWrapped [%s]", string(data)))
	}
	return json.NewDecoder(resp.Body).Decode(v)
}
