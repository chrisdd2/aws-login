package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/chrisdd2/aws-login/internal"
	"github.com/golang-jwt/jwt/v5"
)

type recordingSts struct {
	sessionNames []string
	err          error
}

func (f *recordingSts) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.sessionNames = append(f.sessionNames, aws.ToString(params.RoleSessionName))
	if f.err != nil {
		return nil, f.err
	}
	return &sts.AssumeRoleOutput{Credentials: &stsTypes.Credentials{
		AccessKeyId:     aws.String("AKIA"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
	}}, nil
}

func tokenCookie(t *testing.T, username string, issuedAt time.Time, groups ...string) *http.Cookie {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, internal.UserClaims{
		Username: username,
		Claims:   groups,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(issuedAt),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(8 * time.Hour)),
		},
	}).SignedString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: authCookie, Value: tok}
}

func serve(h http.Handler, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSecurityHeaders(t *testing.T) {
	stsCl := &recordingSts{}
	h := testRouterWith(t, stsCl, nil)
	for _, p := range []string{"/", "/role/111111111111/dev?format=bash", "/login?error=token_expired"} {
		rec := serve(h, p, sessionCookie(t, "devs"))
		want := map[string]string{
			"Cache-Control":          "no-store",
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
		}
		for k, v := range want {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", p, k, got, v)
			}
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
			t.Errorf("%s: missing frame-ancestors csp", p)
		}
		if rec.Header().Get("Strict-Transport-Security") != "" {
			t.Errorf("%s: hsts set without secure cookies", p)
		}
	}
}

func TestSecurityHeadersHstsWhenSecure(t *testing.T) {
	h := Router(context.Background(), nil, "/", "test", testKey, true, time.Hour, nil, nil, nil)
	rec := serve(h, "/login?error=token_expired", nil)
	if rec.Header().Get("Strict-Transport-Security") == "" {
		t.Fatal("expected hsts header when cookies are secure")
	}
}

func TestStaleTokenReauthenticatesSilently(t *testing.T) {
	rec := serve(testRouter(t), "/role/111111111111/dev?format=bash", tokenCookie(t, "alice", time.Now().Add(-2*time.Hour), "devs"))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	var found bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == returnCookie && c.Value == "/role/111111111111/dev?format=bash" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected return cookie so the user lands back after re-authenticating")
	}
}

func TestTokenWithoutIssuedAtIsStale(t *testing.T) {
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, internal.UserClaims{
		Username:         "alice",
		Claims:           []string{"devs"},
		RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))},
	}).SignedString(testKey)
	if err != nil {
		t.Fatal(err)
	}
	rec := serve(testRouter(t), "/", &http.Cookie{Name: authCookie, Value: tok})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestFreshTokenIsAccepted(t *testing.T) {
	rec := serve(testRouter(t), "/", tokenCookie(t, "alice", time.Now().Add(-30*time.Minute), "devs"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestLoginErrorDoesNotReflectInput(t *testing.T) {
	for _, code := range []string{"wrong_credentials", "user_not_found", "anything_else"} {
		q := url.Values{"error": {code}, "message": {"call evil.example"}, "username": {"evil.example"}}
		if msg := loginErrorString(q); strings.Contains(msg, "evil.example") {
			t.Errorf("%s: message reflects input: %q", code, msg)
		}
	}
}

func TestInternalErrorsAreNotExposed(t *testing.T) {
	stsCl := &recordingSts{err: errors.New("AccessDenied: arn:aws:iam::111111111111:role/secret-internal")}
	rec := serve(testRouterWith(t, stsCl, nil), "/role/111111111111/dev?format=bash", sessionCookie(t, "devs"))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret-internal") {
		t.Fatalf("internal error leaked: %s", rec.Body.String())
	}
}

func TestCredentialsUseSanitizedSessionName(t *testing.T) {
	stsCl := &recordingSts{}
	rec := serve(testRouterWith(t, stsCl, nil), "/role/111111111111/dev?format=bash", tokenCookie(t, "John Smith", time.Now(), "devs"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if len(stsCl.sessionNames) != 1 || stsCl.sessionNames[0] != "John-Smith" {
		t.Fatalf("session names %v", stsCl.sessionNames)
	}
}

func TestLogoutWithoutSessionClearsCookie(t *testing.T) {
	rec := serve(testRouter(t), "/logout", &http.Cookie{Name: authCookie, Value: "garbage"})
	var cleared bool
	for _, c := range rec.Result().Cookies() {
		if c.Name == authCookie && c.MaxAge < 0 && c.Path == "/" {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected auth cookie to be cleared")
	}
}

func TestSecureCookiesSetting(t *testing.T) {
	cases := []struct {
		setting, redirect string
		want              bool
	}{
		{"", "https://login.example.com/oauth2/callback", true},
		{"", "http://localhost:8080/oauth2/callback", false},
		{"false", "https://login.example.com/oauth2/callback", false},
		{"true", "http://localhost:8080/oauth2/callback", true},
	}
	for _, c := range cases {
		if got := secureCookies(c.setting, c.redirect); got != c.want {
			t.Errorf("secureCookies(%q, %q) = %v, want %v", c.setting, c.redirect, got, c.want)
		}
	}
}

func TestValidateTokenKey(t *testing.T) {
	if validateTokenKey("short") == nil {
		t.Error("expected short key to be rejected")
	}
	if err := validateTokenKey(strings.Repeat("k", 32)); err != nil {
		t.Errorf("32 character key rejected: %s", err)
	}
}
