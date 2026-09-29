package main

import (
	"context"
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
	return testRouterWith(t, nil)
}

func testRouterWith(t *testing.T, stsCl internal.AssumeRoleClient) http.Handler {
	t.Helper()
	roles := []internal.Role{
		{Name: "dev", AccountId: "111111111111", Claim: []string{"devs"}},
		{Name: "admin", AccountId: "222222222222", Claim: []string{"admins"}},
	}
	return Router(context.Background(), nil, "/", "test", testKey, false, time.Hour, roles, stsCl)
}

func sessionCookie(t *testing.T, groups ...string) *http.Cookie {
	t.Helper()
	tok, err := internal.SignToken(testKey, "alice", groups, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: authCookie, Value: tok}
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

func TestPostNotLoggedInSkipsReturnCookie(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", nil)
	rec := httptest.NewRecorder()
	testRouter(t).ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == returnCookie {
			t.Fatalf("return cookie should not be set for POST")
		}
	}
}

func TestAssumeRoleRejectsInvalidRedirect(t *testing.T) {
	for _, dest := range []string{"https://evil.com/", "http://console.aws.amazon.com/", "javascript:alert(1)"} {
		rec := serve(testRouter(t), "/role/111111111111/dev?redirectUrl="+url.QueryEscape(dest), sessionCookie(t, "devs"))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", dest, rec.Code)
		}
	}
}

func TestAssumeRoleRedirectNoRoleAccess(t *testing.T) {
	rec := serve(testRouter(t), "/role/222222222222/admin?redirectUrl="+url.QueryEscape(awsConsole), sessionCookie(t, "devs"))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestIndexLinksDialog(t *testing.T) {
	roles := []internal.Role{
		{Name: "dev", AccountId: "111111111111", Claim: []string{"devs"}, Links: []internal.Link{
			{Url: "https://s3.console.aws.amazon.com/s3/buckets/b?region=eu-west-1", Description: "Data bucket"},
			{Url: "https://console.aws.amazon.com/lambda/home"},
		}},
		{Name: "ops", AccountId: "333333333333", Claim: []string{"devs"}},
	}
	h := Router(context.Background(), nil, "/", "test", testKey, false, time.Hour, roles, nil)
	rec := serve(h, "/", sessionCookie(t, "devs"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	want := []string{
		`data-dialog="links-0"`,
		`<dialog id="links-0"`,
		`href="/role/111111111111/dev?redirectUrl=https%3A%2F%2Fs3.console.aws.amazon.com%2Fs3%2Fbuckets%2Fb%3Fregion%3Deu-west-1"`,
		`href="/role/111111111111/dev?redirectUrl=https%3A%2F%2Fconsole.aws.amazon.com%2Flambda%2Fhome"`,
		`Data bucket`,
	}
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("index missing %q", w)
		}
	}
	if strings.Contains(body, `links-1"`) {
		t.Errorf("role without links should not render a links dialog")
	}
}
