package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type RolePermissionClaim struct {
	RoleName   string
	Account    int
	AccessType string
}

type AuthInfo struct {
	Username string
	Email    string
}

type AuthService interface {
	RedirectUrl() string
	CallbackEndpoint() string
	CallbackHandler(r *http.Request) (*AuthInfo, error)
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

func (g *GithubService) CallbackHandler(r *http.Request) (*AuthInfo, error) {
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
	return &AuthInfo{Username: loginInfo.Login, Email: userEmail}, nil
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

type OpenIdService struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauthCfg *oauth2.Config
}

func NewOpenId(ctx context.Context, providerUrl string, redirectUrl string, clientId string, clientSecret string) (*OpenIdService, error) {

	provider, err := oidc.NewProvider(ctx, providerUrl)
	if err != nil {
		return nil, fmt.Errorf("oidc.NewProvider %w", err)
	}
	verifier := provider.VerifierContext(ctx, &oidc.Config{
		ClientID: clientId,
	})
	cfg := oauth2.Config{
		ClientID:     clientId,
		ClientSecret: clientSecret,
		RedirectURL:  redirectUrl,
		Endpoint:     provider.Endpoint(),
		Scopes: []string{
			oidc.ScopeOpenID,
			"email",
			"profile",
			"roles",
		},
	}
	return &OpenIdService{
		oauthCfg: &cfg,
		verifier: verifier,
		provider: provider,
	}, nil
}

func (g *OpenIdService) RedirectUrl() string {
	return g.oauthCfg.AuthCodeURL("")
}

func (g *OpenIdService) CallbackEndpoint() string {
	return "/oauth2/idpresponse"
}
func (g *OpenIdService) CallbackHandler(r *http.Request) (*AuthInfo, error) {
	ctx := r.Context()
	code := r.URL.Query().Get("code")
	if code == "" {
		return nil, errors.New("query.Get [missing code parameter]")
	}
	token, err := g.oauthCfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("oauth2.Exchange %w", err)
	}
	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("token.Extra [missing id_token in token]")
	}
	idToken, err := g.verifier.Verify(ctx, idTokenRaw)
	if err != nil {
		return nil, fmt.Errorf("oidc.Verify %w", err)
	}

	type realmAccess struct {
		Roles []string `json:"roles"`
	}
	type accessClaims struct {
		RealmAccess    realmAccess    `json:"realm_access"`
		ResourceAccess map[string]any `json:"resource_access"`
		AwsRoles       []string       `json:"aws_roles"`
	}
	type Claims struct {
		jwt.MapClaims
		accessClaims
	}
	claims := Claims{}
	_, _, err = jwt.NewParser().ParseUnverified(token.AccessToken, &claims)
	if err != nil {
		return nil, fmt.Errorf("token.ParseUnverified %w", err)
	}
	if err := idToken.Claims(&claims.MapClaims); err != nil {
		return nil, fmt.Errorf("idToken.Claims %w", err)
	}

	// user info
	email, _ := claims.MapClaims["email"].(string)
	username, _ := claims.MapClaims["name"].(string)
	preferred_username, _ := claims.MapClaims["preferred_username"].(string)
	if preferred_username != "" {
		username = preferred_username
	}
	if username == "" {
		username = email
	}
	return &AuthInfo{
		Email:    claims.MapClaims["email"].(string),
		Username: username,
	}, nil

}

func parseRoleAttribute(attr string) RolePermissionClaim {
	claim := RolePermissionClaim{}
	for pair := range strings.SplitSeq(attr, ";") {
		k, v, found := strings.Cut(pair, ":")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		fmt.Println(k, v)
		switch k {
		case "access_type":
			claim.AccessType = rolePermissionFromString(v)
		case "account":
			claim.Account, _ = strconv.Atoi(v)
		case "role_name":
			claim.RoleName = v
		}
	}
	return claim
}

func rolePermissionFromString(permission string) string {
	fmt.Println(permission)
	permission = strings.ToLower(permission)
	switch permission {
	case "grant", "assume", "credentials":
		return permission
	default:
		return "invalid"
	}
}

func debugPrint(claims jwt.MapClaims) {
	for k, v := range claims {
		fmt.Println(k, "=", v)
	}
}
