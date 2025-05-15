package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

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

type GithubAuth struct {
	ClientSecret string
	ClientId     string
}

func (g *GithubAuth) RedirectUrl() string {
	return generateGithubAuthUrl(g.ClientId, []string{"user"})
}

var ErrCannotFindEmail error = errors.New("unable to determine github email")

func (g *GithubAuth) HandleCallback(r *http.Request) (*UserInfo, error) {
	code := r.URL.Query().Get("code")
	url := generateGithubAccessToken(g.ClientId, g.ClientSecret, code)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	token := struct {
		AccessToken string `json:"access_token"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&token)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	loginInfo := struct {
		Login string `json:"login"`
	}{}
	err = fetchJsonAuthed(GithubUserApiUrl, token.AccessToken, &loginInfo)
	if err != nil {
		return nil, err
	}
	emails := []struct {
		Email    string `json:"email,omitempty"`
		Verified bool   `json:"verified,omitempty"`
		Primary  bool   `json:"primary,omitempty"`
	}{}
	err = fetchJsonAuthed(GIthubUserEmailApiUrl, token.AccessToken, &emails)
	if err != nil {
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
	return &UserInfo{Username: loginInfo.Login, Email: userEmail}, err
}

func fetchJsonAuthed(url string, accessToken string, v any) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(v)
}
