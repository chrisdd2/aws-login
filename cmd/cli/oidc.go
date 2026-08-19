package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidAuthState    = errors.New("invalid oauth state")
	ErrMissingPkceVerifier = errors.New("missing pkce verifier")
	ErrMissingAuthCode     = errors.New("missing code parameter")
	ErrMissingIdToken      = errors.New("missing id_token in token")
)

type OpenIdService struct {
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauthCfg *oauth2.Config
	opts     *OidcOptions
}

type OidcOptions struct {
	IssuerUrl             string
	LogoutUrl             string
	RedirectUrl           string
	ClientId              string
	ClientSecret          string
	Scopes                []string
	GroupClaimsPath       string
	UsernameClaimsPath    string
	DisplayNameClaimsPath string
	SecureCookies         bool
}

type UserInfo struct {
	DisplayName string
	Username    string
	Groups      []string
}

func joinArrays(a []string, b []string) []string {
	for _, i := range b {
		if slices.Contains(a, i) {
			continue
		}
		a = append(a, i)
	}
	return a
}

func NewOpenId(ctx context.Context, opts *OidcOptions) (*OpenIdService, error) {

	provider, err := oidc.NewProvider(ctx, opts.IssuerUrl)
	if err != nil {
		return nil, fmt.Errorf("oidc.NewProvider %w", err)
	}

	verifier := provider.VerifierContext(ctx, &oidc.Config{
		ClientID: opts.ClientId,
	})

	cfg := oauth2.Config{
		ClientID:     opts.ClientId,
		ClientSecret: opts.ClientSecret,
		RedirectURL:  opts.RedirectUrl,
		Endpoint:     provider.Endpoint(),
		Scopes:       joinArrays([]string{oidc.ScopeOpenID, "email", "profile"}, opts.Scopes),
	}
	if opts.GroupClaimsPath == "" {
		opts.GroupClaimsPath = "roles"
	}
	if opts.UsernameClaimsPath == "" {
		opts.GroupClaimsPath = "email"
	}
	if opts.DisplayNameClaimsPath == "" {
		opts.DisplayNameClaimsPath = "preferred_username"
	}
	if opts.LogoutUrl == "" {
		logoutUrl, err := findLogoutUrl(opts.IssuerUrl)
		if err != nil {
			return nil, err
		}
		opts.LogoutUrl = logoutUrl
	}
	return &OpenIdService{
		oauthCfg: &cfg,
		verifier: verifier,
		provider: provider,
	}, nil
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
		Secure:   g.opts.SecureCookies,
		SameSite: http.SameSiteStrictMode,
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
		Secure:   g.opts.SecureCookies,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	url := g.oauthCfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
	)

	http.Redirect(w, r, url, http.StatusFound)
}

func (g *OpenIdService) CallbackHandler(r *http.Request) (*UserInfo, error) {
	ctx := r.Context()
	query := r.URL.Query()

	// redirects validation
	state := query.Get("state")
	stateCookie, err := r.Cookie("oauth_state")
	if err != nil || state != stateCookie.Value {
		return nil, ErrInvalidAuthState
	}

	pkceCookie, err := r.Cookie("pkce_verifier")
	if err != nil {
		return nil, ErrMissingPkceVerifier
	}
	code := query.Get("code")
	if code == "" {
		return nil, ErrMissingAuthCode
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
		return nil, ErrMissingIdToken
	}
	idToken, err := g.verifier.Verify(ctx, idTokenRaw)
	if err != nil {
		return nil, fmt.Errorf("oidc.Verify %w", err)
	}

	claims := map[string]interface{}{}

	if err := idToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("idToken.Claims %w", err)
	}
	userInfo := UserInfo{}

	userInfo.DisplayName, err = jsonExtract[string](claims, g.opts.DisplayNameClaimsPath)
	if err != nil {
		return nil, err
	}
	userInfo.Groups, err = jsonExtract[[]string](claims, g.opts.GroupClaimsPath)
	if err != nil {
		return nil, err
	}
	userInfo.Username, err = jsonExtract[string](claims, g.opts.UsernameClaimsPath)
	if err != nil {
		return nil, err
	}
	return &userInfo, nil
}

func jsonExtract[T any](j map[string]interface{}, path string) (ret T, err error) {
	parts := strings.Split(path, ".")
	key := parts[len(parts)-1]
	parts = parts[:len(parts)-1]
	for _, i := range parts {
		v, ok := j[i]
		if !ok {
			return ret, errors.New("not found")
		}
		j2, ok := v.(map[string]interface{})
		if !ok {
			return ret, errors.New("not found")
		}
		j = j2
	}
	v, ok := j[key]
	if !ok {
		return *new(T), errors.New("not found")
	}
	ret, ok = v.(T)
	if !ok {
		return *new(T), errors.New("not found")
	}
	return ret, nil
}

func (g *OpenIdService) LogoutUrl(redirectUrl string, idpToken string) string {
	values := url.Values{}
	values.Add("id_token_hint", idpToken)
	values.Add("post_logout_redirect_uri", redirectUrl)
	return fmt.Sprintf("%s/?%s", strings.TrimSuffix(g.opts.LogoutUrl, "/"), values.Encode())
}

func findLogoutUrl(issuer string) (string, error) {
	// find the logout url
	wellKnown := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	info := struct {
		EndSessionEndpoint string `json:"end_session_endpoint"`
	}{}
	resp, err := http.Get(wellKnown)
	if err != nil {
		return "", fmt.Errorf("http.Get: %w", err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("json.Decode: %w", err)
	}
	return info.EndSessionEndpoint, nil
}
