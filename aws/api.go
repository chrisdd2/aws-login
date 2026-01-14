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
	cfnTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
)

// some unique identifiers we might need
const (
	StackName    = AccountIdentifier("aws-login-stack-%s")
	OpsRole      = AccountIdentifier("ops-role-role-%s")
	boundaryName = AccountIdentifier("iam-role-boundary-%s")
	signInUrl    = "https://signin.aws.amazon.com/federation"
)

var (
	ErrInvalidCfnResponse = errors.New("invalid response from cfn api")
	ErrStackNotExist      = errors.New("stack doesn't exist")
	ErrNotAuthorized      = errors.New("management role doesn't exist or missing permissions")
	// one working day, unless you slave away
	DefaultSessionDuration = int32((time.Hour * 8).Seconds())
)

type StackEvent struct {
	EventTime            time.Time
	ResourceId           string
	ResourceType         string
	ResourceStatus       string
	ResourceStatusReason string
}

func (s StackEvent) Color() string {
	switch cfnTypes.ResourceStatus(s.ResourceStatus) {
	case cfnTypes.ResourceStatusCreateInProgress, cfnTypes.ResourceStatusDeleteInProgress, cfnTypes.ResourceStatusImportInProgress, cfnTypes.ResourceStatusUpdateInProgress, cfnTypes.ResourceStatusImportRollbackInProgress, cfnTypes.ResourceStatusExportRollbackInProgress, cfnTypes.ResourceStatusUpdateRollbackInProgress, cfnTypes.ResourceStatusRollbackInProgress, cfnTypes.ResourceStatusExportInProgress:
		return "yellow"
	case cfnTypes.ResourceStatusCreateComplete, cfnTypes.ResourceStatusDeleteComplete, cfnTypes.ResourceStatusDeleteSkipped, cfnTypes.ResourceStatusUpdateComplete, cfnTypes.ResourceStatusImportComplete, cfnTypes.ResourceStatusExportComplete:
		return "green"
	case cfnTypes.ResourceStatusCreateFailed, cfnTypes.ResourceStatusDeleteFailed, cfnTypes.ResourceStatusUpdateFailed, cfnTypes.ResourceStatusImportFailed, cfnTypes.ResourceStatusExportFailed, cfnTypes.ResourceStatusExportRollbackFailed, cfnTypes.ResourceStatusImportRollbackFailed, cfnTypes.ResourceStatusImportRollbackComplete, cfnTypes.ResourceStatusExportRollbackComplete, cfnTypes.ResourceStatusUpdateRollbackComplete, cfnTypes.ResourceStatusUpdateRollbackFailed, cfnTypes.ResourceStatusRollbackComplete, cfnTypes.ResourceStatusRollbackFailed:
		return "red"
	}
	switch cfnTypes.StackStatus(s.ResourceStatus) {
	case cfnTypes.StackStatusUpdateRollbackCompleteCleanupInProgress, cfnTypes.StackStatusUpdateCompleteCleanupInProgress:
		return "indigo"
	}
	return "grey"
}

type AwsApiCaller interface {
	WhoAmI(ctx context.Context) (account string, arn string, err error)
	GetCredentials(ctx context.Context, roleArn string, sessionName string) (
		AccessKeyId string,
		SecretAccessKey string,
		SessionToken string,
		err error)
	DeployStack(ctx context.Context, accountName string, accountId string, stackName string, templateText string, params map[string]string) error
	DestroyStack(ctx context.Context, accountName string, accountId string, stackName string) (stackId string, error error)
	TopStackEvents(ctx context.Context, accountName string, accountId string, stackName string) ([]StackEvent, error)
	StackTemplate(ctx context.Context, accountName string, accountId string, stackName string) (string, error)
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

func (a *apiImpl) StackTemplate(ctx context.Context, accountName string, accountId string, stackName string) (string, error) {
	cfg, err := assumeRole(ctx, a.stsCl, arnForRole(accountId, OpsRole.Value(accountName)))
	if err != nil {
		return "", fmt.Errorf("assumeRole: %w", err)
	}
	cfnCl := cloudformation.NewFromConfig(cfg)
	resp, err := cfnCl.GetTemplate(ctx, &cloudformation.GetTemplateInput{
		StackName:     &stackName,
		TemplateStage: cfnTypes.TemplateStageOriginal,
	})
	if isStackMissingErr(err) {
		return "", ErrStackNotExist
	}
	if err != nil {

		return "", fmt.Errorf("cloudformation.GetTemplate: %w", err)
	}
	return aws.ToString(resp.TemplateBody), nil
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

func (a *apiImpl) DestroyStack(ctx context.Context, accountName string, accountId string, stackName string) (stackId string, err error) {
	cfg, err := assumeRole(ctx, a.stsCl, arnForRole(accountId, OpsRole.Value(accountName)))
	if err != nil {
		return "", err
	}
	cfnCl := cloudformation.NewFromConfig(cfg)
	resp, err := cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackName})
	if isStackMissingErr(err) {
		return "", ErrStackNotExist
	}
	if err != nil {
		return "", err
	}
	_, err = cfnCl.DeleteStack(ctx, &cloudformation.DeleteStackInput{StackName: &stackName})
	if err != nil {
		return "", fmt.Errorf("cloudformation.DeleteStack: %w", err)
	}
	if len(resp.Stacks) > 0 && resp.Stacks[0].StackId != nil {
		return *resp.Stacks[0].StackId, nil
	}
	return "", ErrInvalidCfnResponse
}
func (a *apiImpl) DeployStack(ctx context.Context, accountName string, accountId string, stackName string, templateText string, params map[string]string) error {
	cfg, err := assumeRole(ctx, a.stsCl, arnForRole(accountId, OpsRole.Value(accountName)))
	if err != nil {
		return err
	}
	cfnCl := cloudformation.NewFromConfig(cfg)
	if params == nil {
		params = map[string]string{}
	}
	params["ManagementRoleArn"] = a.arn
	params["PermissionBoundaryName"] = boundaryName.Value(accountName)
	return updateStack(ctx, cfnCl, stackName, templateText, params)
}

func updateStack(ctx context.Context, cfnCl *cloudformation.Client, stackName string, templateString string, params map[string]string) error {
	cfnParams := []cfnTypes.Parameter{}
	for k, v := range params {
		cfnParams = append(cfnParams, cfnTypes.Parameter{
			ParameterKey:   &k,
			ParameterValue: &v,
		})
	}

	_, err := cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackName})
	update := true
	if err != nil {
		if isStackMissingErr(err) {
			update = false
		} else {
			return err
		}
	}
	if update {
		_, err = cfnCl.UpdateStack(ctx, &cloudformation.UpdateStackInput{
			StackName:    &stackName,
			TemplateBody: &templateString,
			Parameters:   cfnParams,
			Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam},
		})
		if err != nil && !isNoUpdateErr(err) {
			return err
		}
		return nil
	}
	_, err = cfnCl.CreateStack(ctx, &cloudformation.CreateStackInput{
		StackName:    &stackName,
		TemplateBody: &templateString,
		Parameters:   cfnParams,
		Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam},
	})
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
	// sanity check for assume role permissions
	if _, err := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		// check if its an authorization error
		var o *smithy.GenericAPIError
		if errors.As(err, &o) {
			if o.Code == "AccessDenied" && strings.Contains(o.Message, "sts:AssumeRole") {
				return cfg, ErrNotAuthorized
			}
		}
		return cfg, err
	}
	return cfg, nil
}

func getStack(ctx context.Context, cfnCl *cloudformation.Client, stackName string) (cfnTypes.Stack, error) {
	resp, err := cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackName})
	if isStackMissingErr(err) {
		return cfnTypes.Stack{}, ErrStackNotExist
	}
	if err != nil {
		return cfnTypes.Stack{}, fmt.Errorf("cfn.DescribeStacks: %w", err)
	}
	if len(resp.Stacks) == 0 {
		return cfnTypes.Stack{}, ErrStackNotExist
	}
	return resp.Stacks[0], nil
}

func (a *apiImpl) TopStackEvents(ctx context.Context, accountName string, accountId string, stackName string) ([]StackEvent, error) {
	cfg, err := assumeRole(ctx, a.stsCl, arnForRole(accountId, OpsRole.Value(accountName)))
	if err != nil {
		return nil, err
	}

	cfnCl := cloudformation.NewFromConfig(cfg)
	resp, err := cfnCl.DescribeStackEvents(ctx, &cloudformation.DescribeStackEventsInput{StackName: &stackName})
	if err != nil {
		return nil, err
	}
	ret := make([]StackEvent, 0, len(resp.StackEvents))
	for _, ev := range resp.StackEvents {
		ret = append(ret, StackEvent{
			EventTime:            aws.ToTime(ev.Timestamp).UTC(),
			ResourceId:           aws.ToString(ev.LogicalResourceId),
			ResourceType:         aws.ToString(ev.ResourceType),
			ResourceStatus:       aws.ToString((*string)(&ev.ResourceStatus)),
			ResourceStatusReason: aws.ToString(ev.ResourceStatusReason),
		})
	}
	return ret, nil
}

type AccountIdentifier string

func (a AccountIdentifier) Value(accountName string) string {
	return fmt.Sprintf(string(a), accountName)
}
