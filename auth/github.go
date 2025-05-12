package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

const GithubAuthUrl = "https://github.com/login/oauth/authorize"
const GithubAccessTokenUrl = "https://github.com/login/oauth/access_token"
const GithubUserApiUrl = "https://api.github.com/user"

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

// ?scope=user:email&client_id=<%= client_id %

type GithubAuth struct {
	ClientSecret string
	ClientId     string
}


func (g *GithubAuth) RedirectUrl() string {
	return generateGithubAuthUrl(g.ClientId, []string{"user:email"})
}

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
	req, err = http.NewRequest("GET", "https://api.github.com/user", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	loginInfo := struct {
		Login string `json:"login"`
	}{}
	err = json.NewDecoder(resp.Body).Decode(&loginInfo)
	return &UserInfo{Username: loginInfo.Login}, err
}
