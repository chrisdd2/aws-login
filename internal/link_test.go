package internal

import (
	"testing"
	"time"
)

func TestLinkTokenRoundTrip(t *testing.T) {
	key := []byte("secret")
	cases := []LinkClaims{
		{Account: "123456789012", Role: "admin", Url: "https://s3.console.aws.amazon.com/s3/buckets/b"},
		{Account: "000000000042", Role: "data-engineer", Url: "https://eu-west-1.console.aws.amazon.com/glue/home?region=eu-west-1#/v2/data-catalog/tables"},
		{Account: "999999999999", Role: "", Url: "https://x.aws.amazon.com/"},
		{Account: "111111111111", Role: "r", Url: "https://zq9.aws.amazon.com/Zx7Qp2Lw8Vn4Kt6Jy1Hs3Gd5Fb0Mc"},
	}
	for _, c := range cases {
		token, err := SignLinkToken(key, c.Account, c.Role, c.Url)
		if err != nil {
			t.Fatal(err)
		}
		claims, err := ParseLinkToken(key, token)
		if err != nil {
			t.Fatalf("%+v: %s", c, err)
		}
		if *claims != c {
			t.Fatalf("got %+v, want %+v", claims, c)
		}
	}
}

func TestLinkTokenSize(t *testing.T) {
	u := "https://s3.console.aws.amazon.com/s3/buckets/my-data-bucket?region=eu-west-1&bucketType=general&tab=objects"
	token, err := SignLinkToken([]byte("secret"), "123456789012", "data-engineer", u)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("url %d chars, token %d chars", len(u), len(token))
	if len(token) >= len(u) {
		t.Fatalf("token (%d) should be shorter than the url (%d)", len(token), len(u))
	}
}

func TestLinkTokenInvalidAccount(t *testing.T) {
	for _, a := range []string{"", "12345", "12345678901a", "1234567890123"} {
		if _, err := SignLinkToken([]byte("secret"), a, "r", "https://console.aws.amazon.com/"); err == nil {
			t.Fatalf("expected account %q to be rejected", a)
		}
	}
}

func TestLinkTokenRejected(t *testing.T) {
	key := []byte("secret")
	valid, err := SignLinkToken(key, "123456789012", "admin", "https://console.aws.amazon.com/")
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := SignLinkToken([]byte("other"), "123456789012", "admin", "https://console.aws.amazon.com/")
	if err != nil {
		t.Fatal(err)
	}
	session, err := SignToken(key, "alice", []string{"devs"}, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tampered := []byte(valid)
	i := len(tampered) - 5
	if tampered[i] == 'A' {
		tampered[i] = 'B'
	} else {
		tampered[i] = 'A'
	}

	cases := map[string]string{
		"tampered":  string(tampered),
		"other key": otherKey,
		"session":   session,
		"garbage":   "favicon.ico",
		"empty":     "",
	}
	for name, tok := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseLinkToken(key, tok); err == nil {
				t.Fatalf("expected %s token to be rejected", name)
			}
		})
	}
}
