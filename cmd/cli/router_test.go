package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chrisdd2/aws-login/internal"
)

var testKey = []byte("test-key")

func testRouter(t *testing.T) http.Handler {
	t.Helper()
	return testRouterWith(t, nil, nil)
}

func testRouterWith(t *testing.T, stsCl internal.AssumeRoleClient, ssmClients SsmClientFactory) http.Handler {
	t.Helper()
	roles := []internal.Role{
		{Name: "dev", AccountId: "111111111111", Claim: []string{"devs"}},
		{Name: "admin", AccountId: "222222222222", Claim: []string{"admins"}},
		{Name: "ops", AccountId: "333333333333", Claim: []string{"devs"}, SsmEnabled: true},
		{Name: "ops-admin", AccountId: "444444444444", Claim: []string{"admins"}, SsmEnabled: true},
	}
	return Router(context.Background(), nil, "/", "test", testKey, false, roles, stsCl, ssmClients)
}

func sessionCookie(t *testing.T, groups ...string) *http.Cookie {
	t.Helper()
	tok, err := internal.SignToken(testKey, "alice", groups, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: authCookie, Value: tok}
}

func postLink(t *testing.T, h http.Handler, path string, dest string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"url": {dest}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestValidAwsUrl(t *testing.T) {
	cases := map[string]bool{
		"https://s3.console.aws.amazon.com/s3/buckets/my-bucket?region=eu-west-1": true,
		"https://console.aws.amazon.com/":                                         true,
		"https://aws.amazon.com/":                                                 true,
		"http://console.aws.amazon.com/":                                          false,
		"https://evil.com/":                                                       false,
		"https://aws.amazon.com.evil.com/":                                        false,
		"https://evilaws.amazon.com/":                                             false,
		"https://user@console.aws.amazon.com/":                                    false,
		"javascript:alert(1)":                                                     false,
		"/relative":                                                               false,
		"":                                                                        false,
	}
	for in, want := range cases {
		if got := validAwsUrl(in); got != want {
			t.Errorf("validAwsUrl(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestNormalizeAwsUrl(t *testing.T) {
	cases := map[string]string{
		"https://123456789012-abc12xyz.eu-west-1.console.aws.amazon.com/s3/buckets/b?region=eu-west-1": "https://eu-west-1.console.aws.amazon.com/s3/buckets/b?region=eu-west-1",
		"https://123456789012-ABC12XYZ.us-east-1.console.aws.amazon.com/iam/home#/roles":               "https://us-east-1.console.aws.amazon.com/iam/home#/roles",
		"https://eu-west-1.console.aws.amazon.com/s3/home":                                             "https://eu-west-1.console.aws.amazon.com/s3/home",
		"https://s3.console.aws.amazon.com/s3/buckets/b":                                               "https://s3.console.aws.amazon.com/s3/buckets/b",
		"https://12345-abc.eu-west-1.console.aws.amazon.com/":                                          "https://12345-abc.eu-west-1.console.aws.amazon.com/",
		"https://123456789012-abc.aws.amazon.com/":                                                     "https://123456789012-abc.aws.amazon.com/",
	}
	for in, want := range cases {
		if got := normalizeAwsUrl(in); got != want {
			t.Errorf("normalizeAwsUrl(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCreateLinkStripsMultiSession(t *testing.T) {
	rec := postLink(t, testRouter(t), "/role/111111111111/dev/link", "https://111111111111-x9y8z7.eu-west-1.console.aws.amazon.com/s3/buckets/b", sessionCookie(t, "devs"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	resp := struct {
		Url string `json:"url"`
	}{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	claims, err := internal.ParseLinkToken(testKey, strings.TrimPrefix(resp.Url, "/"))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Url != "https://eu-west-1.console.aws.amazon.com/s3/buckets/b" {
		t.Fatalf("unexpected url %q", claims.Url)
	}
}

func TestSafeReturnPath(t *testing.T) {
	cases := map[string]bool{
		"/abc":             true,
		"/":                true,
		"//evil.com":       false,
		"/\\evil.com":      false,
		"https://evil.com": false,
		"":                 false,
	}
	for in, want := range cases {
		if got := safeReturnPath(in); got != want {
			t.Errorf("safeReturnPath(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestCreateLink(t *testing.T) {
	h := testRouter(t)
	dest := "https://s3.console.aws.amazon.com/s3/buckets/my-bucket"
	rec := postLink(t, h, "/role/111111111111/dev/link", dest, sessionCookie(t, "devs"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	resp := struct {
		Url string `json:"url"`
	}{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(resp.Url, "/") || strings.Count(resp.Url, "/") != 1 {
		t.Fatalf("unexpected url %q", resp.Url)
	}
	claims, err := internal.ParseLinkToken(testKey, strings.TrimPrefix(resp.Url, "/"))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Account != "111111111111" || claims.Role != "dev" || claims.Url != dest {
		t.Fatalf("unexpected claims %+v", claims)
	}
}

func TestCreateLinkBadUrl(t *testing.T) {
	rec := postLink(t, testRouter(t), "/role/111111111111/dev/link", "https://evil.com/", sessionCookie(t, "devs"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestCreateLinkNoRoleAccess(t *testing.T) {
	rec := postLink(t, testRouter(t), "/role/222222222222/admin/link", "https://console.aws.amazon.com/", sessionCookie(t, "devs"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestCreateLinkNotLoggedIn(t *testing.T) {
	rec := postLink(t, testRouter(t), "/role/111111111111/dev/link", "https://console.aws.amazon.com/", nil)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == returnCookie {
			t.Fatalf("return cookie should not be set for POST")
		}
	}
}

func TestFollowLinkInvalidToken(t *testing.T) {
	h := testRouter(t)
	for _, p := range []string{"/favicon.ico", "/garbage"} {
		req := httptest.NewRequest(http.MethodGet, p, nil)
		req.AddCookie(sessionCookie(t, "devs"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: status %d", p, rec.Code)
		}
	}
}

func TestFollowLinkNoRoleAccess(t *testing.T) {
	tok, err := internal.SignLinkToken(testKey, "222222222222", "admin", "https://console.aws.amazon.com/")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/"+tok, nil)
	req.AddCookie(sessionCookie(t, "devs"))
	rec := httptest.NewRecorder()
	testRouter(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestFollowLinkNotLoggedInSetsReturnCookie(t *testing.T) {
	tok, err := internal.SignLinkToken(testKey, "111111111111", "dev", "https://console.aws.amazon.com/")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/"+tok, nil)
	rec := httptest.NewRecorder()
	testRouter(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	var found *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == returnCookie {
			found = c
		}
	}
	if found == nil || found.Value != "/"+tok {
		t.Fatalf("expected return cookie with path, got %+v", found)
	}
}

func TestIndexHasUrlButton(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(sessionCookie(t, "devs"))
	rec := httptest.NewRecorder()
	testRouter(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-link="/role/111111111111/dev/link"`) || !strings.Contains(body, `id="url-dialog"`) {
		t.Fatalf("index missing url button or dialog")
	}
}
