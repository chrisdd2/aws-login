package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/template"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cfnTypes "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/embed"
)

var cfnTemplates *template.Template

func cfnRenderTemplate(name string, data any) (string, error) {
	buf := bytes.Buffer{}
	err := cfnTemplates.ExecuteTemplate(&buf, name, data)
	return buf.String(), err

}

func init() {
	cfnTemplates = template.Must(template.ParseFS(embed.CloudFormationFs, "cfn/*.template.yml"))
}

func PrincipalFromSts(arn string) string {
	if strings.Contains(arn, ":user/") {
		return arn
	} else if strings.Contains(arn, ":assumed-role/") {
		//arn:aws:sts::123456789012:assumed-role/SomeRole/i-0abcdef1234567890//
		//arn:aws:iam::123456789012:role/SomeRole
		parts := strings.Split(arn, ":")
		fmt.Println(parts)
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
	return cfnTemplates.ExecuteTemplate(w, "bootstrap.template.yml", struct {
		OpsRoleName string
		Principal   string
	}{OpsRole, PrincipalFromSts(*resp.Arn)})
}

// some unique identifiers we might need
const uniqueId = "8db7bc11-acf5-4c7a-be46-967f44e33028"
const StackName = "aws-login-stack-" + uniqueId
const OpsRole = "ops-role-role-" + uniqueId
const developerRole = "developer-role-" + uniqueId
const readOnlyRole = "read-only-role-" + uniqueId

type CfnClient interface {
	CreateStack(ctx context.Context, params *cloudformation.CreateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.CreateStackOutput, error)
	UpdateStack(ctx context.Context, params *cloudformation.UpdateStackInput, optFns ...func(*cloudformation.Options)) (*cloudformation.UpdateStackOutput, error)
	DescribeStacks(ctx context.Context, params *cloudformation.DescribeStacksInput, optFns ...func(*cloudformation.Options)) (*cloudformation.DescribeStacksOutput, error)
}

func DeployBaseStack(ctx context.Context, cfnCl CfnClient) error {
	tmpl, err := cfnRenderTemplate("base.template.yml", nil)
	if err != nil {
		return err
	}
	stackName := aws.String(StackName)
	_, err = cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: stackName})
	update := true
	if err != nil {
		var error *cfnTypes.StackNotFoundException
		if !errors.As(err, &error) {
			return err
		}
		// stack doesn't exist
		update = false
	}
	cfnParams := []cfnTypes.Parameter{
		{ParameterKey: aws.String("DeveloperRoleName"), ParameterValue: aws.String(developerRole)},
		{ParameterKey: aws.String("ReadOnlyRoleName"), ParameterValue: aws.String(readOnlyRole)},
		{ParameterKey: aws.String("ManagementRoleName"), ParameterValue: aws.String(OpsRole)},
	}
	if update {
		_, err = cfnCl.UpdateStack(ctx, &cloudformation.UpdateStackInput{StackName: stackName, TemplateBody: &tmpl, Parameters: cfnParams})
		return err
	}
	_, err = cfnCl.CreateStack(ctx, &cloudformation.CreateStackInput{StackName: stackName, TemplateBody: &tmpl, Parameters: cfnParams})
	return err
}
