package internal

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
)

func TestManagedByAwsLogin(t *testing.T) {
	cases := []struct {
		tags []iamTypes.Tag
		want bool
	}{
		{nil, false},
		{[]iamTypes.Tag{{Key: aws.String("team"), Value: aws.String("x")}}, false},
		{[]iamTypes.Tag{{Key: aws.String("aws-login"), Value: aws.String("false")}}, false},
		{[]iamTypes.Tag{{Key: aws.String("team"), Value: aws.String("x")}, {Key: aws.String("aws-login"), Value: aws.String("true")}}, true},
	}
	for _, c := range cases {
		if got := managedByAwsLogin(c.tags); got != c.want {
			t.Errorf("managedByAwsLogin(%v) = %v, want %v", c.tags, got, c.want)
		}
	}
}

func TestMapToAwsTagsMarksManaged(t *testing.T) {
	if !managedByAwsLogin(mapToAwsTags(map[string]string{"team": "x"})) {
		t.Fatal("roles created by aws-login must carry the managed tag")
	}
}

func TestBoundaryChange(t *testing.T) {
	arn := "arn:aws:iam::111111111111:policy/b"
	cases := []struct {
		current, want string
		action        boundaryAction
	}{
		{"", "", boundaryKeep},
		{arn, arn, boundaryKeep},
		{"", arn, boundaryPut},
		{"arn:aws:iam::111111111111:policy/other", arn, boundaryPut},
		{arn, "", boundaryDelete},
	}
	for _, c := range cases {
		if got := boundaryChange(c.current, c.want); got != c.action {
			t.Errorf("boundaryChange(%q, %q) = %v, want %v", c.current, c.want, got, c.action)
		}
	}
}

func TestSessionName(t *testing.T) {
	cases := map[string]string{
		"alice":             "alice",
		"alice@example.com": "alice@example.com",
		"John Smith":        "John-Smith",
		"a":                 "aws-login-a",
		"":                  "aws-login-",
		"ünïcode/name":      "-n-code-name",
	}
	for in, want := range cases {
		if got := SessionName(in); got != want {
			t.Errorf("SessionName(%q) = %q, want %q", in, got, want)
		}
	}
	long := SessionName(string(make([]byte, 100)))
	if len(long) != 64 {
		t.Errorf("long session name has length %d, want 64", len(long))
	}
}
