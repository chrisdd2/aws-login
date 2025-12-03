package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	cfnTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
)

// some unique identifiers we might need
const (
	UniqueId     = "dde2ab66-f68a-4d3d-a9d5-0a66690c7695"
	StackName    = "aws-login-stack-" + UniqueId
	OpsRole      = "ops-role-role-" + UniqueId
	boundaryName = "iam-role-boundary-" + UniqueId
	signInUrl    = "https://signin.aws.amazon.com/federation"
)

var (
	ErrInvalidCfnResponse = errors.New("invalid response from cfn api")
	// one working day, unless you slave away
	DefaultSessionDuration = int32((time.Hour * 8).Seconds())
)

type StackEvent struct {
	EventTime      time.Time
	ResourceId     string
	ResourceType   string
	ResourceStatus string
}

type AwsApiCaller interface {
	WhoAmI(ctx context.Context) (account string, arn string, err error)
	GetCredentials(ctx context.Context, roleArn string, sessionName string) (
		AccessKeyId string,
		SecretAccessKey string,
		SessionToken string,
		err error)
	DeployStack(ctx context.Context, account string, stackName string, templateText string, params map[string]string) error
	DestroyStack(ctx context.Context, account string, stackName string) (stackId string, error error)
	WatchStackEvents(ctx context.Context, account string, stackName string) (iter.Seq2[[]StackEvent, error], error)
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
	_, _, err := ret.WhoAmI(ctx)
	if err != nil {
		return nil, err
	}
	return &ret, nil
}

func (a *apiImpl) WhoAmI(ctx context.Context) (account string, arn string, err error) {
	if a.account == "" {
		resp, err := a.stsCl.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		if err != nil {
			return "", "", err
		}
		a.account = aws.ToString(resp.Account)
		a.arn = aws.ToString(resp.Arn)
		a.roleName = principalFromArn(a.arn)
	}
	return a.account, a.arn, nil
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

func (a *apiImpl) DestroyStack(ctx context.Context, account string, stackName string) (stackId string, err error) {
	cfg, err := assumeRole(ctx, a.stsCl, arnForRole(account, OpsRole))
	if err != nil {
		return "", err
	}
	cfnCl := cloudformation.NewFromConfig(cfg)
	resp, err := cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackName})
	if err != nil && !isStackMissingErr(err) {
		return "", err
	}
	_, err = cfnCl.DeleteStack(ctx, &cloudformation.DeleteStackInput{StackName: &stackName})
	if len(resp.Stacks) > 1 && resp.Stacks[0].StackId != nil {
		return *resp.Stacks[0].StackId, nil
	}
	return "", ErrInvalidCfnResponse
}
func (a *apiImpl) WatchStackEvents(ctx context.Context, account string, stackName string) (iter.Seq2[[]StackEvent, error], error) {
	cfg, err := assumeRole(ctx, a.stsCl, arnForRole(account, OpsRole))
	if err != nil {
		return nil, err
	}

	cfnCl := cloudformation.NewFromConfig(cfg)
	getStackEvents := func(latestEventTime time.Time) ([]StackEvent, time.Time, error) {
		events := []StackEvent{}
		resp, err := cfnCl.DescribeStackEvents(ctx, &cloudformation.DescribeStackEventsInput{
			StackName: &stackName,
		})
		if err != nil {
			return nil, latestEventTime, err
		}
		// its reverse order so reverse it for the user
		for _, ev := range slices.Backward(resp.StackEvents) {
			evTime := aws.ToTime(ev.Timestamp).UTC()
			if !evTime.After(latestEventTime) {
				continue
			}
			events = append(events, StackEvent{
				EventTime:      evTime,
				ResourceId:     aws.ToString(ev.LogicalResourceId),
				ResourceType:   aws.ToString(ev.ResourceType),
				ResourceStatus: aws.ToString(ev.ResourceStatusReason),
			})
			latestEventTime = evTime
		}
		return events, latestEventTime.UTC(), nil
	}

	return func(yield func([]StackEvent, error) bool) {
		latestTime := time.Time{}
		for {
			events, t, err := getStackEvents(latestTime)
			if !yield(events, err) {
				break
			}
			latestTime = t
		}
	}, nil
}

func (a *apiImpl) DeployStack(ctx context.Context, account string, stackName string, templateText string, params map[string]string) error {
	cfg, err := assumeRole(ctx, a.stsCl, arnForRole(account, OpsRole))
	if err != nil {
		return err
	}
	cfnCl := cloudformation.NewFromConfig(cfg)
	_, err = cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackName})
	update := true
	if err != nil {
		if isStackMissingErr(err) {
			update = false
		} else {
			return err
		}
	}
	cfnParams := []cfnTypes.Parameter{
		{ParameterKey: aws.String("ManagementRoleArn"), ParameterValue: &a.arn},
		{ParameterKey: aws.String("PermissionBoundaryName"), ParameterValue: aws.String(boundaryName)},
	}
	for k, v := range params {
		cfnParams = append(cfnParams, cfnTypes.Parameter{
			ParameterKey:   &k,
			ParameterValue: &v,
		})
	}
	if update {
		_, err = cfnCl.UpdateStack(ctx, &cloudformation.UpdateStackInput{StackName: &stackName, TemplateBody: &templateText, Parameters: cfnParams, Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam}})
		if err != nil && !isNoUpdateErr(err) {
			return err
		}
		return nil
	}
	_, err = cfnCl.CreateStack(ctx, &cloudformation.CreateStackInput{StackName: &stackName, TemplateBody: &templateText, Parameters: cfnParams, Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam}})
	return err

}

func (a *apiImpl) GenerateSigninUrl(ctx context.Context, roleArn string, sessionName string, redirectUrl string) (string, error) {
	accessKeyId, secretAccessKey, sessionToken, err := a.GetCredentials(ctx, roleArn, sessionName)
	if err != nil {
		return "", err
	}
	// request sign in token from federation page
	token := struct {
		SessionId    string `json:"sessionId"`
		SessionKey   string `json:"sessionKey"`
		SessionToken string `json:"sessionToken"`
	}{accessKeyId, secretAccessKey, sessionToken}

	tokenStr, _ := json.Marshal(token)
	values := url.Values{
		"Action":          []string{"getSigninToken"},
		"SessionDuration": []string{strconv.Itoa(int(DefaultSessionDuration))},
		"Session":         []string{string(tokenStr)},
	}

	awsResp, err := http.Get(fmt.Sprintf("%s?%s", signInUrl, values.Encode()))
	if err != nil {
		return "", err
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
		return aws.Config{}, err
	}
	return cfg, nil
}
