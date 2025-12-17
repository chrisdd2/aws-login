package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type RolePermissionClaim struct {
	RoleName   string
	Account    int
	AccessType string
}

type AuthInfo struct {
	Username     string
	FriendlyName string
	IdpToken     string
}

type AuthServiceDetails struct {
	Endpoint string
	Name     string
}

type AuthService interface {
	Details() AuthServiceDetails
	LogoutUrl(redirectUrl string, idpToken string) string
	TokenLogin(r *http.Request, tokenString string) (*AuthInfo, error)
	Login(w http.ResponseWriter, r *http.Request)
	CallbackHandler(r *http.Request) (*AuthInfo, error)
}

const (
	GithubAuthUrl         = "https://github.com/login/oauth/authorize"
	GithubAccessTokenUrl  = "https://github.com/login/oauth/access_token"
	GithubUserApiUrl      = "https://api.github.com/user"
	GIthubUserEmailApiUrl = "https://api.github.com/user/emails"
)

func generateGithubAccessTokenUrl(clientId, clientSecret, sessionCode string) string {
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

func (g *GithubService) Details() AuthServiceDetails {
	return AuthServiceDetails{
		Endpoint: g.AuthResponsePath,
		Name:     "github",
	}
}
func (g *GithubService) LogoutUrl(redirectUrl string, idpToken string) string {
	return "/"
}

var ErrCannotFindEmail error = errors.New("unable to determine github email")

func (g *GithubService) Login(w http.ResponseWriter, r *http.Request) {
	values := url.Values{}
	scopes := []string{"user"}
	for _, scope := range scopes {
		values.Add("scope", scope)
	}
	values.Add("client_id", g.ClientId)
	http.Redirect(w, r, fmt.Sprintf("%s?%s", GithubAuthUrl, values.Encode()), http.StatusFound)
}

func (g *GithubService) CallbackHandler(r *http.Request) (*AuthInfo, error) {
	code := r.URL.Query().Get("code")
	url := generateGithubAccessTokenUrl(g.ClientId, g.ClientSecret, code)
	token := struct {
		AccessToken string `json:"access_token"`
	}{}
	if err := getWrapped(url, map[string]string{
		"Accept": "application/json",
	}, http.StatusOK, &token); err != nil {
		return nil, err
	}
	return g.TokenLogin(r, token.AccessToken)
}

func (g *GithubService) TokenLogin(r *http.Request, tokenString string) (*AuthInfo, error) {
	loginInfo := struct {
		Login string `json:"login"`
	}{}
	if err := fetchJsonAuthed(GithubUserApiUrl, tokenString, &loginInfo); err != nil {
		return nil, err
	}
	emails := []struct {
		Email    string `json:"email,omitempty"`
		Verified bool   `json:"verified,omitempty"`
		Primary  bool   `json:"primary,omitempty"`
	}{}
	if err := fetchJsonAuthed(GIthubUserEmailApiUrl, tokenString, &emails); err != nil {
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
	return &AuthInfo{FriendlyName: loginInfo.Login, Username: userEmail}, nil
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
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauthCfg    *oauth2.Config
	name        string
	endpoint    string
	logoutUrl   string
	validations []OpenIdClaimsValidation
}

func findLogoutUrl(issuer string) (string, error) {
	// find the logout url
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	info := struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}{}
	resp, err := http.Get(wellKnown)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.EndSessionEndpoint, nil
}

type OpenIdClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	PreferredName string `json:"preferred_username"`
	HD            string `json:"hd"`
	Sub           string `json:"sub"`
}

type OpenIdClaimsValidation func(claims OpenIdClaims) error

func NewOpenId(ctx context.Context, name string, providerUrl string, redirectUrl string, clientId string, clientSecret string, validations ...OpenIdClaimsValidation) (*OpenIdService, error) {
	parsedUrl, err := url.Parse(redirectUrl)
	if err != nil {
		return nil, fmt.Errorf("url.Parse %w", err)
	}
	endpoint := fmt.Sprintf("/%s", strings.TrimSuffix(strings.TrimPrefix(parsedUrl.Path, "/"), "/"))

	provider, err := oidc.NewProvider(ctx, providerUrl)
	if err != nil {
		return nil, fmt.Errorf("oidc.NewProvider %w", err)
	}
	logoutUrl, err := findLogoutUrl(providerUrl)
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
		},
	}
	return &OpenIdService{
		oauthCfg:    &cfg,
		verifier:    verifier,
		provider:    provider,
		logoutUrl:   logoutUrl,
		endpoint:    endpoint,
		name:        name,
		validations: validations,
	}, nil
}

func (g *OpenIdService) Details() AuthServiceDetails {
	return AuthServiceDetails{
		Endpoint: g.endpoint,
		Name:     g.name,
	}
}
func (g *OpenIdService) Login(w http.ResponseWriter, r *http.Request) {
	// random verification
	stateBuf := make([]byte, 32)
	rand.Read(stateBuf)
	state := base64.RawURLEncoding.EncodeToString(stateBuf)
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	codeVerifierBuf := make([]byte, 32)
	rand.Read(codeVerifierBuf)
	codeVerifierSha := sha256.Sum256(codeVerifierBuf)
	codeVerifier := base64.RawURLEncoding.EncodeToString(codeVerifierSha[:])
	http.SetCookie(w, &http.Cookie{
		Name:     "pkce_verifier",
		Value:    codeVerifier,
		HttpOnly: true,
		Secure:   false,
		Path:     "/",
	})

	url := g.oauthCfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
	)

	http.Redirect(w, r, url, http.StatusFound)
}

func (g *OpenIdService) CallbackHandler(r *http.Request) (*AuthInfo, error) {
	ctx := r.Context()
	query := r.URL.Query()

	// redirects validation
	state := query.Get("state")
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || state != stateCookie.Value {
		return nil, errors.New("invalid oauth state")
	}

	pkceCookie, err := r.Cookie("pkce_verifier")
	if err != nil {
		return nil, errors.New("missing pkce verifier")
	}
	code := query.Get("code")
	if code == "" {
		return nil, errors.New("query.Get [missing code parameter]")
	}
	token, err := g.oauthCfg.Exchange(ctx,
		code,
		oauth2.VerifierOption(pkceCookie.Value),
	)
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

	claims := OpenIdClaims{}
	for _, v := range g.validations {
		if err := v(claims); err != nil {
			return nil, fmt.Errorf("claimValidation: %w", err)
		}
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("idToken.Claims %w", err)
	}

	name := claims.Name
	if claims.PreferredName != "" {
		name = claims.PreferredName
	}
	if name == "" {
		name = claims.Email
	}

	// user info
	return &AuthInfo{
		Username:     claims.Email,
		FriendlyName: name,
		IdpToken:     idTokenRaw,
	}, nil

}

func (g *OpenIdService) LogoutUrl(redirectUrl string, idpToken string) string {
	values := url.Values{}
	values.Add("id_token_hint", idpToken)
	values.Add("post_logout_redirect_uri", redirectUrl)
	return fmt.Sprintf("%s/?%s", strings.TrimSuffix(g.logoutUrl, "/"), values.Encode())
}

func (g *OpenIdService) TokenLogin(r *http.Request, tokenString string) (*AuthInfo, error) {
	return nil, fmt.Errorf("not implemented")
}
