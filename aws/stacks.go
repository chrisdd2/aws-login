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
)

var cfnTemplates *template.Template

// some unique identifiers we might need
const (
	uniqueId      = "8db7bc11-acf5-4c7a-be46-967f44e33028"
	StackName     = "aws-login-stack-" + uniqueId
	OpsRole       = "ops-role-role-" + uniqueId
	DeveloperRole = "developer-role-" + uniqueId
	ReadOnlyRole  = "read-only-role-" + uniqueId
	boundaryName  = "iam-role-boundary-" + uniqueId
)

func init() {
	cfnTemplates = template.Must(template.ParseFS(cfn.CloudFormationFs, "*.template"))
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
		OpsRoleName string
		Principal   string
	}{OpsRole, PrincipalFromSts(*resp.Arn)})
}

type CfnClient interface {
	CreateStack(ctx context.Context, params *cloudformation.CreateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	UpdateStack(ctx context.Context, params *cloudformation.UpdateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.UpdateStackOutput, error)
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

func DeployBaseStack(ctx context.Context, cfnCl CfnClient, managementRoleArn string) error {
	buf := bytes.Buffer{}
	err := cfnTemplates.ExecuteTemplate(&buf, "base.template", nil)
	if err != nil {
		return err
	}
	tmpl := buf.String()
	stackName := aws.String(StackName)
	_, err = cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: stackName})
	update := true
	if err != nil {
		var apiErr smithy.APIError
		if !errors.As(err, &apiErr) {
			return err
		}
		if !(apiErr.ErrorCode() == "ValidationError" && strings.Contains(apiErr.ErrorMessage(), "does not exist")) {
			return err
		}
		update = false
	}
	cfnParams := []cfnTypes.Parameter{
		{ParameterKey: aws.String("DeveloperRoleName"), ParameterValue: aws.String(DeveloperRole)},
		{ParameterKey: aws.String("ReadOnlyRoleName"), ParameterValue: aws.String(ReadOnlyRole)},
		{ParameterKey: aws.String("ManagementRoleArn"), ParameterValue: &managementRoleArn},
		{ParameterKey: aws.String("PermissionBoundaryName"), ParameterValue: aws.String(boundaryName)},
		{ParameterKey: aws.String("MaxSessionDuration"), ParameterValue: aws.String(strconv.Itoa(int((time.Hour * 8) / time.Second)))},
	}
	if update {
		_, err = cfnCl.UpdateStack(ctx, &cloudformation.UpdateStackInput{StackName: stackName, TemplateBody: &tmpl, Parameters: cfnParams, Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam}})
		if err != nil {
			var apiErr smithy.APIError
			if !errors.As(err, &apiErr) {
				return err
			}
			if apiErr.ErrorMessage() != "No updates are to be performed." {
				return err
			}
		}
		return nil
	}
	_, err = cfnCl.CreateStack(ctx, &cloudformation.CreateStackInput{StackName: stackName, TemplateBody: &tmpl, Parameters: cfnParams, Capabilities: []cfnTypes.Capability{cfnTypes.CapabilityCapabilityNamedIam}})
	return err
}
