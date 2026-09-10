package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

const signInUrl = "https://signin.aws.amazon.com/federation"

var ErrNotAuthorized = errors.New("management role doesn't exist or missing permissions")

type AwsCredentials struct {
	AccessKeyId     string `json:"aws_access_key_id,omitempty"`
	SecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	SessionToken    string `json:"aws_session_token,omitempty"`
}

const (
	CredentialFormatCmd        = "cmd"
	CredentialFormatPowershell = "powershell"
	CredentialFormatBash       = "bash"
)

type CredentialFormatType string

func (c AwsCredentials) Format(t string) string {
	switch t {
	case CredentialFormatCmd:
		return fmt.Sprintf("set AWS_ACCESS_KEY_ID=%s\nset AWS_SECRET_ACCESS_KEY=%s\nset AWS_SESSION_TOKEN=%s", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	case CredentialFormatPowershell:
		return fmt.Sprintf("$env:AWS_ACCESS_KEY_ID=\"%s\"\n$env:AWS_SECRET_ACCESS_KEY=\"=%s\"\n$env:AWS_SESSION_TOKEN=\"%s\"", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	case CredentialFormatBash:
		return fmt.Sprintf("export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\nexport AWS_SESSION_TOKEN=%s", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	default:
		// just json
		buf, _ := json.Marshal(c)
		return string(buf)
	}
}

type AssumeRoleClient interface {
	AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
}

func GenerateCredentials(ctx context.Context, cl AssumeRoleClient, roleArn string, sessionName string, duration time.Duration) (AwsCredentials, error) {
	resp, err := cl.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: &sessionName, DurationSeconds: aws.Int32(int32(duration.Seconds()))})
	if err != nil {
		return AwsCredentials{}, WrapError(err, "AssumeRoleClient.AssumeRole")
	}
	return AwsCredentials{
		AccessKeyId:     aws.ToString(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(resp.Credentials.SessionToken),
	}, nil
}

func GenerateSignedUrl(ctx context.Context, creds AwsCredentials, redirectUrl string, duration time.Duration) (string, error) {
	// request sign in token from federation page
	token := struct {
		SessionId    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{
		SessionId:    creds.AccessKeyId,
		SessionKey:   creds.SecretAccessKey,
		SessionToken: creds.SessionToken,
	}

	tokenStr, _ := json.Marshal(token) // Error handled below; empty string is acceptable
	values := url.Values{
		"Action":          []string{"getSigninToken"},
		"SessionDuration": []string{strconv.Itoa(int(duration.Seconds()))},
		"Session":         []string{string(tokenStr)},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s?%s", signInUrl, values.Encode()), nil)
	if err != nil {
		return "", WrapError(err, "http.NewRequestWithContext")
	}
	awsResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", WrapError(err, "http.Get")
	}
	defer awsResp.Body.Close()
	if awsResp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(awsResp.Body)
		fmt.Fprintf(os.Stderr, "status_code: %d\n:text: %s\n", awsResp.StatusCode, string(data))
		return "", WrapError(errors.New(awsResp.Status), "aws.getSigninToken")
	}

	signinToken := struct {
		SigninToken string `json:"SigninToken"`
	}{}
	err = json.NewDecoder(awsResp.Body).Decode(&signinToken)
	if err != nil {
		return "", WrapError(err, "json.Decode")
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

func AssumeRoleConfig(ctx context.Context, stsCl AssumeRoleClient, roleArn string, sessionName string, duration time.Duration) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(stscreds.NewAssumeRoleProvider(stsCl, roleArn, func(aro *stscreds.AssumeRoleOptions) {
		aro.RoleSessionName = sessionName
		aro.Duration = duration
	})))
	if err != nil {
		return aws.Config{}, WrapError(err, "config.LoadDefaultConfig")
	}
	// sanity check for assume role permissions
	if _, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		// check if its an authorization error
		if o, ok := errors.AsType[*smithy.GenericAPIError](err); ok {
			if o.Code == "AccessDenied" && strings.Contains(o.Message, "sts:AssumeRole") {
				return cfg, ErrNotAuthorized
			}
		}
		return cfg, WrapError(err, "sts.GetCallerIdentity")
	}
	return cfg, nil
}

