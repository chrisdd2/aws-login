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

	"github.com/chrisdd2/aws-login/internal"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidAuthState    = errors.New("invalid oauth state")
	ErrMissingPkceVerifier = errors.New("missing pkce verifier")
	ErrMissingAuthCode     = errors.New("missing code parameter")
	ErrMissingIdToken      = errors.New("missing id_token in token")
	ErrNotFound            = errors.New("not found")
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
	IdToken     string
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
		return nil, internal.WrapError(err, "oidc.NewProvider")
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
		opts.UsernameClaimsPath = "email"
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
		opts:     opts,
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
		SameSite: http.SameSiteLaxMode,
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
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	url := g.oauthCfg.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(codeVerifier),
	)

	internal.Debugf("oidc.Login: redirecting to provider %s", url)
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
		return nil, internal.WrapError(err, "oauth2.Exchange")
	}
	idTokenRaw, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, ErrMissingIdToken
	}
	idToken, err := g.verifier.Verify(ctx, idTokenRaw)
	if err != nil {
		return nil, internal.WrapError(err, "oidc.Verify")
	}

	claims := map[string]interface{}{}

	if err := idToken.Claims(&claims); err != nil {
		return nil, internal.WrapError(err, "idToken.Claims")
	}
	internal.Debugf("oidc.CallbackHandler: raw id_token claims: %+v", claims)
	userInfo := UserInfo{}

	userInfo.DisplayName, err = jsonExtract(claims, g.opts.DisplayNameClaimsPath)
	if err != nil {
		return nil, err
	}
	userInfo.Groups, err = jsonExtractStrings(claims, g.opts.GroupClaimsPath)
	if err != nil {
		return nil, err
	}
	internal.Debugf("oidc.CallbackHandler: extracted groups from %q: %v", g.opts.GroupClaimsPath, userInfo.Groups)
	userInfo.Username, err = jsonExtract(claims, g.opts.UsernameClaimsPath)
	if err != nil {
		return nil, err
	}
	userInfo.IdToken = idTokenRaw
	return &userInfo, nil
}

func jsonExtractValue(j map[string]interface{}, path string) (interface{}, error) {
	parts := strings.Split(path, ".")
	for _, p := range parts[:len(parts)-1] {
		v, ok := j[p]
		if !ok {
			return nil, ErrNotFound
		}
		next, ok := v.(map[string]interface{})
		if !ok {
			return nil, ErrNotFound
		}
		j = next
	}
	v, ok := j[parts[len(parts)-1]]
	if !ok {
		return nil, ErrNotFound
	}
	return v, nil
}

func jsonExtract(j map[string]interface{}, path string) (string, error) {
	v, err := jsonExtractValue(j, path)
	if err != nil {
		return "", err
	}
	return fmt.Sprint(v), nil
}

func jsonExtractStrings(j map[string]interface{}, path string) ([]string, error) {
	v, err := jsonExtractValue(j, path)
	if err != nil {
		return nil, err
	}
	items, ok := v.([]interface{})
	if !ok {
		return []string{fmt.Sprint(v)}, nil
	}
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = fmt.Sprint(item)
	}
	return out, nil
}

func (g *OpenIdService) PostLogoutRedirectUrl(path string, query url.Values) string {
	u, err := url.Parse(g.opts.RedirectUrl)
	if err != nil {
		// fall back to whatever was configured, better than crashing
		return path
	}
	u.Path = path
	u.RawQuery = query.Encode()
	return u.String()
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
		return "", internal.WrapError(err, "http.Get: %w")
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", internal.WrapError(err, "json.Decode")
	}
	return info.EndSessionEndpoint, nil
}
