package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfnTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/chrisdd2/aws-login/aws/cfn"
	"github.com/chrisdd2/aws-login/storage"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var cfnTemplates *template.Template

// some unique identifiers we might need
const (
	StackName    = "aws-login-stack-" + storage.UniqueId
	OpsRole      = "ops-role-role-" + storage.UniqueId
	boundaryName = "iam-role-boundary-" + storage.UniqueId
)

func init() {
	tmpl := template.New("stacks").Funcs(
		template.FuncMap{
			"roleLogicalName": func(roleName string) string {
				// remove invalid characters
				normalized := strings.ReplaceAll(strings.ReplaceAll(roleName, "-", " "), "/", " ")
				// capitalize
				normalized = cases.Title(language.English, cases.Compact).String(strings.ToLower(normalized))
				// remove spaces
				return strings.Join(strings.Split(normalized, " "), "")
			},
			"maxSessionDuration": func(duration time.Duration) string {
				return strconv.Itoa(int((duration) / time.Second))
			},
		})
	cfnTemplates = template.Must(tmpl.ParseFS(cfn.CloudFormationFs, "*.template"))
}

func PrincipalFromSts(arn string) string {
	if strings.Contains(arn, ":user/") {
		return arn
	} else if strings.Contains(arn, ":assumed-role/") {
		//arn:aws:sts::123456789012:assumed-role/SomeRole/i-0abcdef1234567890//
		//arn:aws:iam::123456789012:role/SomeRole
		parts := strings.Split(arn, ":")
		roleNameParts := strings.Split(parts[5], "/")
		return fmt.Sprintf("arn:aws:iam::%s:role/%s", parts[4], roleNameParts[1])
	}
	return arn
}

func BootstrapTemplate(ctx context.Context, stsCl StsClient, w io.Writer) error {
	resp, err := stsCl.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return err
	}
	return cfnTemplates.ExecuteTemplate(w, "bootstrap.template", struct {
		OpsRoleName     string
		Principal       string
		TargetStackName string
	}{OpsRole, PrincipalFromSts(*resp.Arn), StackName})
}

type CfnClient interface {
	CreateStack(ctx context.Context, params *cloudformation.CreateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	UpdateStack(ctx context.Context, params *cloudformation.UpdateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.UpdateStackOutput, error)
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
	DeleteStack(ctx context.Context, params *cloudformation.DeleteStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DeleteStackOutput, error)
}

func DeployBaseStack(ctx context.Context, cfnCl CfnClient, managementRoleArn string, roles []storage.Role) (string, error) {
	buf := bytes.Buffer{}
	err := cfnTemplates.ExecuteTemplate(&buf, "base.template", struct{ Roles []storage.Role }{Roles: roles})
	if err != nil {
		return "", err
	}
	tmpl := buf.String()
	stackName := aws.String(StackName)
	_, err = cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: stackName})
	update := true
	if err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			return "", err
		}
		if !(apiErr.ErrorCode() == "ValidationError" && strings.Contains(apiErr.ErrorMessage(), "does not exist")) {
			return "", err
		}
		update = false
	}
	cfnParams := []cfnTypes.Parameter{
		{ParameterKey: aws.String("ManagementRoleArn"), ParameterValue: &managementRoleArn},
		{ParameterKey: aws.String("PermissionBoundaryName"), ParameterValue: aws.String(boundaryName)},
	}
	if update {
		_, err = cfnCl.UpdateStack(ctx, &cloudformation.UpdateStackInput{StackName: stackName, TemplateBody: &tmpl, Parameters: cfnParams, Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam}})
		if err != nil {
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) {
				return "", err
			}
			if apiErr.ErrorMessage() != "No updates are to be performed." {
				return "", err
			}
		}
		return StackName, nil
	}
	_, err = cfnCl.CreateStack(ctx, &cloudformation.CreateStackInput{StackName: stackName, TemplateBody: &tmpl, Parameters: cfnParams, Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam}})
	return StackName, err
}
func DestroyBaseStack(ctx context.Context, cfnCl CfnClient, managementRoleArn string) (string, error) {
	stackName := aws.String(StackName)
	resp, err := cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: stackName})
	if err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			return "", err
		}
		if !(apiErr.ErrorCode() == "ValidationError" && strings.Contains(apiErr.ErrorMessage(), "does not exist")) {
			return "", err
		}
		return "", err
	}
	_, err = cfnCl.DeleteStack(ctx, &cloudformation.DeleteStackInput{StackName: stackName})
	return *resp.Stacks[0].StackId, nil
}
