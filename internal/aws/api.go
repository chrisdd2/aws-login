package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

// some unique identifiers we might need
const (
	signInUrl = "https://signin.aws.amazon.com/federation"
)

var (
	ErrInvalidCfnResponse = errors.New("invalid response from cfn api")
	ErrStackNotExist      = errors.New("stack doesn't exist")
	ErrNotAuthorized      = errors.New("management role doesn't exist or missing permissions")
	// one working day, unless you slave away
	DefaultSessionDuration = int32((time.Hour * 8).Seconds())
)

type AwsApiCaller interface {
	GetCredentials(ctx context.Context, roleArn string, sessionName string) (
		AccessKeyId string,
		SecretAccessKey string,
		SessionToken string,
		err error)
	GenerateSigninUrl(ctx context.Context, roleArn string, sessionName string, redirectUrl string) (string, error)
}
type apiImpl struct {
	stsCl *sts.Client

	account  string
	arn      string
	roleName string
}

func NewAwsApi(ctx context.Context, stsCl *sts.Client) (AwsApiCaller, error) {
	ret := apiImpl{stsCl: stsCl}
	return &ret, nil
}

func (a *apiImpl) GetCredentials(
	ctx context.Context,
	roleArn string,
	sessionName string,
) (
	AccessKeyId string,
	SecretAccessKey string,
	SessionToken string,
	err error) {
	resp, err := a.stsCl.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &roleArn, RoleSessionName: &sessionName, DurationSeconds: &DefaultSessionDuration})
	if err != nil {
		return
	}
	return aws.ToString(resp.Credentials.AccessKeyId),
		aws.ToString(resp.Credentials.SecretAccessKey),
		aws.ToString(resp.Credentials.SessionToken), nil
}

func (a *apiImpl) GenerateSigninUrl(ctx context.Context, roleArn string, sessionName string, redirectUrl string) (string, error) {
	accessKeyId, secretAccessKey, sessionToken, err := a.GetCredentials(ctx, roleArn, sessionName)
	if err != nil {
		return "", err
	}
	return generateSignUrl(ctx, accessKeyId, secretAccessKey, sessionToken, redirectUrl)
}

func generateSignUrl(ctx context.Context, accessKeyId, secretAccessKey, sessionToken, redirectUrl string) (string, error) {
	// request sign in token from federation page
	token := struct {
		SessionId    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{
		SessionId:    accessKeyId,
		SessionKey:   secretAccessKey,
		SessionToken: sessionToken,
	}

	tokenStr, _ := json.Marshal(token) // Error handled below; empty string is acceptable
	values := url.Values{
		"Action":          []string{"getSigninToken"},
		"SessionDuration": []string{strconv.Itoa(int(DefaultSessionDuration))},
		"Session":         []string{string(tokenStr)},
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s?%s", signInUrl, values.Encode()), nil)
	if err != nil {
		return "", fmt.Errorf("http.NewRequestWithContext: %w", err)
	}
	awsResp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("http.Get: %w", err)
	}
	defer awsResp.Body.Close()
	if awsResp.StatusCode != http.StatusOK {
		data, err := io.ReadAll(awsResp.Body)
		return "", errors.Join(err, errors.New(string(data)))
	}

	signinToken := struct {
		SigninToken string `json:"SigninToken"`
	}{}
	err = json.NewDecoder(awsResp.Body).Decode(&signinToken)
	if err != nil {
		return "", fmt.Errorf("json.Decode: %w", err)
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

func isStackMissingErr(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorCode() == "ValidationError" && strings.Contains(apiErr.ErrorMessage(), "does not exist")
}

func isNoUpdateErr(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.ErrorMessage() == "No updates are to be performed."
}
func principalFromArn(arn string) string {
	if strings.Contains(arn, ":user/") {
		return arn
	} else if strings.Contains(arn, ":assumed-role/") {
		//arn:aws:sts::123456789012:assumed-role/SomeRole/i-0abcdef1234567890//
		//arn:aws:iam::123456789012:role/SomeRole
		parts := strings.Split(arn, ":")
		roleNameParts := strings.Split(parts[5], "/")
		return arnForRole(parts[4], roleNameParts[1])
	}
	return arn
}

func arnForRole(account string, roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", account, roleName)
}

func assumeRole(ctx context.Context, stsCl *sts.Client, roleArn string) (aws.Config, error) {
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(stscreds.NewAssumeRoleProvider(stsCl, roleArn, func(aro *stscreds.AssumeRoleOptions) {
		aro.RoleSessionName = "aws-login"
		aro.Duration = time.Minute * 15 // minimum
	})))
	if err != nil {
		return aws.Config{}, fmt.Errorf("config.LoadDefaultConfig: %w", err)
	}
	// sanity check for assume role permissions
	if _, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		// check if its an authorization error
		var o *smithy.GenericAPIError
		if errors.As(err, &o) {
			if o.Code == "AccessDenied" && strings.Contains(o.Message, "sts:AssumeRole") {
				return cfg, ErrNotAuthorized
			}
		}
		return cfg, fmt.Errorf("sts.GetCallerIdentity: %w", err)
	}
	return cfg, nil
}
