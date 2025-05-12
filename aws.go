package main

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// global aws, no cn no gov cloud cause f that
const signInUrl = "https://signin.aws.amazon.com/federation"

// one working day, unless you slave away
var sessionDuration = int32((time.Hour * 8).Seconds())

type RoleFinder interface {
	iam.ListRoleTagsAPIClient
	iam.ListRolesAPIClient
}

func findRolesIterator(ctx context.Context, cl RoleFinder, tagKey string) iter.Seq2[string, error] {
	hasTag := func(roleName string) bool {
		resp, err := cl.ListRoleTags(ctx, &iam.ListRoleTagsInput{RoleName: &roleName})
		if err != nil {
			return false
		}
		for _, tag := range resp.Tags {
			if *tag.Key == tagKey {
				return true
			}
		}
		return false
	}
	return func(yield func(string, error) bool) {
		paginator := iam.NewListRolesPaginator(cl, &iam.ListRolesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				yield("", err)
				return
			}
			for _, role := range page.Roles {
				if !hasTag(*role.RoleName) {
					continue
				}
				if !yield(*role.Arn, nil) {
					return
				}
			}
		}
	}
}

type StsClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

// Generates signin url for aws console for a role
//
// Basically implements the flow describe in the docs (https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_enable-console-custom-url.html)
func generateSigninUrl(ctx context.Context, cl StsClient, roleArn string, sessionName string, redirectUrl string) (string, error) {
	// get credentials
	resp, err := cl.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: &sessionName, DurationSeconds: &sessionDuration})
	if err != nil {
		return "", err
	}

	// request sign in token from federation page
	token := struct {
		SessionId    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{*resp.Credentials.AccessKeyId, *resp.Credentials.SecretAccessKey, *resp.Credentials.SessionToken}

	tokenStr, _ := json.Marshal(token)
	values := url.Values{
		"Action":          []string{"getSigninToken"},
		"SessionDuration": []string{strconv.Itoa(int(sessionDuration))},
		"Session":         []string{string(tokenStr)},
	}

	awsResp, err := http.Get(fmt.Sprintf("%s?%s", signInUrl, values.Encode()))
	if err != nil {
		return "", err
	}
	defer awsResp.Body.Close()

	signinToken := struct {
		SigninToken string `json:"SigninToken"`
	}{}
	err = json.NewDecoder(awsResp.Body).Decode(&signinToken)
	if err != nil {
		return "", err
	}

	// construct signin url
	values = url.Values{
		"Action":      []string{"login"},
		"Issuer":      []string{"aws-login"},
		"Destination": []string{redirectUrl},
		"SigninToken": []string{signinToken.SigninToken},
	}
	return fmt.Sprintf("%s?%s", signInUrl, values.Encode()), nil
}
