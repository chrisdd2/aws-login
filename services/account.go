package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/aws"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type DeploymentStatus struct {
	StackExists    bool
	NeedsUpdate    bool
	NeedsBootstrap bool
}

type AccountService interface {
	Deploy(ctx context.Context, userId string, accountId string) error
	DeploymentStatus(ctx context.Context, accountId string) (DeploymentStatus, error)
	StackUpdates(ctx context.Context, accountName string, stackId string) ([]aws.StackEvent, error)
	DestroyStack(ctx context.Context, accountName string) (string, error)
	GetFromAccountName(ctx context.Context, name string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)
	BootstrapTemplate(ctx context.Context, accountName string, terraform bool) (string, error)
}

const stackHash = "al:stackHash"

type accountService struct {
	storage Storage
	aws     aws.AwsApiCaller
}

var baseStackTemplate = template.Must(template.New("base-stack").Funcs(template.FuncMap{
	"roleLogicalName":    roleLogicalName,
	"maxSessionDuration": maxSessionDuration,
}).Parse(
	`
AWSTemplateFormatVersion: '2010-09-09'
Description: >
  IAM setup with:
    - Permissions boundary to prevent unrestricted IAM user creation
    - Roles for the account assumeable only by specified principal

Parameters:
  ManagementRoleArn:
    Type: String
    Description: Management role arn
  PermissionBoundaryName:
    Type: String
    Description: name for the permission boundary on iam roles

Resources:

  IAMPermissionsBoundary:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: !Ref PermissionBoundaryName
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Sid: DenyAllIAMUserActions
            Effect: Deny
            Action:
              - iam:CreateUser
              - iam:DeleteUser
            Resource: "*"

          - Sid: DenyCreateRoleWithoutBoundary
            Effect: Deny
            Action:
              - iam:CreateRole
            Resource: "*"
            Condition:
              StringNotEqualsIfExists:
                iam:PermissionsBoundary: !Sub "arn:aws:iam::${AWS::AccountId}:policy/${PermissionBoundaryName}"

          - Sid: DenyUpdateRoleToRemoveBoundary
            Effect: Deny
            Action:
              - iam:UpdateRole
            Resource: "*"
            Condition:
              StringNotEqualsIfExists:
                iam:PermissionsBoundary: !Sub "arn:aws:iam::${AWS::AccountId}:policy/${PermissionBoundaryName}"
          - Sid: DenyBoundaryActions
            Effect: Deny
            Action:
              - iam:*Boundary
            Resource: "*"
          - Sid: AllowEverythingElse
            Effect: Allow
            Action:
              - "*"
            Resource: "*"
{{ range .Roles}}
  {{roleLogicalName .RoleName }}:
    Type: AWS::IAM::Role
    Properties:
      RoleName: {{ .RoleName }}
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref ManagementRoleArn
            Action: sts:AssumeRole
      {{ if .ManagedPolicies }}
      ManagedPolicyArns:
        {{range .ManagedPolicies}}
        - {{.}}
        {{end}}
      {{ end }}
      {{ if .Policies }}
      Policies:
      {{ range $key, $value := .Policies }}
        - PolicyName: {{ $key }}
          PolicyDocument: {{ $value }}
      {{ end }}
      {{ end }}
      PermissionsBoundary: !Ref IAMPermissionsBoundary
      MaxSessionDuration: {{ maxSessionDuration .MaxSessionDuration }} 
{{ end }}


Outputs:
  {{ range .Roles}}
  {{ $name := roleLogicalName .RoleName }}
  {{ $name }}Arn:
    Description: Arn of {{.RoleName}}
    Value: !GetAtt {{$name}}.Arn
  {{end}}
`))

func templateExecuteToString[T any](tmpl *template.Template, data T) (string, error) {
	buf := bytes.Buffer{}
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (a *accountService) Deploy(ctx context.Context, userId string, accountId string) error {
	// Permission check
	user, err := a.storage.GetUser(ctx, userId)
	if err != nil {
		return err
	}
	if !(user.Superuser) {
		return errors.New("no permission for this action")
	}

	templateString, err := generateStackTemplate(ctx, a.storage, accountId)
	if err != nil {
		return fmt.Errorf("generateStackTemplate: %w", err)
	}
	h, err := generateStackHash(templateString)
	if err != nil {
		return err
	}

	// Deploy the stack
	account, err := a.storage.GetAccount(ctx, accountId)
	if err != nil {
		return err
	}
	awsAccountId := strconv.Itoa(account.AwsAccountId)
	return a.aws.DeployStack(ctx, account.Name, awsAccountId, aws.StackName.Value(accountId), templateString, nil, map[string]string{stackHash: h})
}
func (a *accountService) GetFromAccountName(ctx context.Context, name string) (*appconfig.Account, error) {
	return a.storage.GetAccount(ctx, name)
}

func roleLogicalName(roleName string) string {
	// remove invalid characters
	normalized := strings.ReplaceAll(strings.ReplaceAll(roleName, "-", " "), "/", " ")
	// capitalize
	normalized = cases.Title(language.English, cases.Compact).String(strings.ToLower(normalized))
	// remove spaces
	return strings.Join(strings.Split(normalized, " "), "")
}
func maxSessionDuration(duration time.Duration) string {
	return strconv.Itoa(int((duration) / time.Second))
}

func ValidateAWSAccountID(accountID int) bool {
	return accountID > 100000000000 && accountID <= 999999999999
}

func NewAccountService(store Storage, aws aws.AwsApiCaller) AccountService {
	return &accountService{
		storage: store,
		aws:     aws,
	}
}

func (a *accountService) ListAccounts(ctx context.Context) ([]*appconfig.Account, error) {
	return a.storage.ListAccounts(ctx)
}

func (a *accountService) DeploymentStatus(ctx context.Context, accountName string) (DeploymentStatus, error) {
	status := DeploymentStatus{
		StackExists:    true,
		NeedsUpdate:    false,
		NeedsBootstrap: false,
	}
	acc, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return status, fmt.Errorf("storage.GetAccount: %w", err)
	}
	templateString, err := generateStackTemplate(ctx, a.storage, acc.Name)
	if err != nil {
		return status, fmt.Errorf("generateStackTemplate: %w", err)
	}
	currentHash, err := generateStackHash(templateString)
	if err != nil {
		return status, err
	}

	tags, err := a.aws.StackTags(ctx, accountName, strconv.Itoa(acc.AwsAccountId), aws.StackName.Value(accountName), nil, true)
	if errors.Is(err, aws.ErrStackNotExist) {
		status.StackExists = false
		return status, nil
	}
	if errors.Is(err, aws.ErrNotAuthorized) {
		status.StackExists = false
		status.NeedsBootstrap = true
		return status, nil
	}
	if err != nil {
		return status, fmt.Errorf("aws.StackTags: %w", err)
	}
	stackHash := tags[stackHash]
	status.NeedsUpdate = stackHash != currentHash
	return status, nil
}
func (a *accountService) StackUpdates(ctx context.Context, accountName string, stackId string) ([]aws.StackEvent, error) {
	acc, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return nil, fmt.Errorf("accountService.StackUpdates: storage.GetAccount: %w", err)
	}
	if stackId == "" {
		stackId = aws.StackName.Value(accountName)
	}
	events, err := a.aws.TopStackEvents(ctx, accountName, acc.AccountId(), stackId)
	if err != nil {
		return nil, fmt.Errorf("accountService.StackUpdates: aws.WatchStackEvents: %w", err)
	}
	return events, nil
}

func generateStackTemplate(ctx context.Context, store Storage, account string) (string, error) {
	// gather up all the roles that need to be deployed as part of the stack
	type CfnRole struct {
		LogicalName        string
		RoleName           string
		ManagedPolicies    []string
		Policies           map[string]string
		MaxSessionDuration time.Duration
	}

	roles, err := store.ListRolesForAccount(ctx, account)
	cfnroles := []CfnRole{}
	for _, item := range roles {
		resolvedPolicies := map[string]string{}
		for name, id := range item.Policies {
			policy, err := store.GetInlinePolicy(ctx, id)
			if err != nil {
				return "", fmt.Errorf("storage.GetInlinePolicy: %w", err)
			}
			resolvedPolicies[name] = policy.Document
		}

		cfnroles = append(cfnroles, CfnRole{
			LogicalName:        roleLogicalName(item.Name),
			RoleName:           item.Name,
			ManagedPolicies:    item.ManagedPolicies,
			Policies:           resolvedPolicies,
			MaxSessionDuration: item.MaxSessionDuration,
		})
	}
	templateString, err := templateExecuteToString(baseStackTemplate, struct{ Roles []CfnRole }{Roles: cfnroles})
	if err != nil {
		return "", err
	}
	return templateString, nil
}

func (a *accountService) DestroyStack(ctx context.Context, accountName string) (string, error) {
	acc, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return "", fmt.Errorf("accountService.DestroyStack: storage.GetAccount: %w", err)
	}
	stackId, err := a.aws.DestroyStack(ctx, accountName, acc.AccountId(), aws.StackName.Value(accountName))
	if err != nil {
		return "", fmt.Errorf("accountService.DestroyStack: aws.DestroyStack: %w", err)
	}
	return stackId, nil

}

func generateStackHash(templateString string) (string, error) {
	h := sha256.New()
	_, err := h.Write([]byte(templateString))
	if err != nil {
		return "", fmt.Errorf("sha256.Write: %w", err)
	}
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

var bootstrapStackTemplateCfn = template.Must(template.New("bootstrap-stack").Parse(`
AWSTemplateFormatVersion: '2010-09-09'
Description: >
  aws-login Bootstrap
  Creates an IAM role with scoped CloudFormation and IAM permissions.
  The role will be used to setup the account.

Parameters:
  AwsLoginPrincipal:
    Type: String
    Description: ARN of the IAM user or role that can assume this admin role
    Default: {{.Principal}}

  TargetStackName:
    Type: String
    Description: Name of the CloudFormation stack this role will manage
    Default: {{.TargetStackName}}

Resources:
  OpsRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: {{.OpsRoleName}}
      AssumeRolePolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Ref AwsLoginPrincipal
            Action: sts:AssumeRole
      Policies:
        - PolicyName: StackAndIAMManagement
          PolicyDocument:
            Version: "2012-10-17"
            Statement:
              - Sid: AllowSpecificStackOperations
                Effect: Allow
                Action:
                  - cloudformation:CreateStack
                  - cloudformation:UpdateStack
                  - cloudformation:DeleteStack
                  - cloudformation:DescribeStacks
                  - cloudformation:DescribeStackEvents
                Resource: !Sub arn:aws:cloudformation:${AWS::Region}:${AWS::AccountId}:stack/${TargetStackName}/*

              - Sid: AllowFullIAMViaCloudFormation
                Effect: Allow
                Action: "iam:*"
                Resource: "*"
                Condition:
                  ForAnyValue:StringEquals:
                    aws:CalledVia: cloudformation.amazonaws.com

              - Sid: AllowPassRole
                Effect: Allow
                Action: iam:PassRole
                Resource: "*"

      MaxSessionDuration: 43200

Outputs:
  OpsRoleArn:
    Description: ARN of the management role
    Value: !GetAtt OpsRole.Arn`))
var bootstrapStackTemplateTerraform = template.Must(template.New("bootstrap-stack-tf").Parse(`
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.25.0"
    }
  }
}

provider "aws" {
  region = "eu-west-1"
}

variable "aws_login_user" {
  type        = string
  default     = "{{.Principal}}"
  description = "Principal allowed to assume the ops role"
}

variable "account_name" {
  type = string
  default = "{{.AccountName}}"
  description = "identifier for the account"
}

locals {
  ops_role_name = "{{.OpsRoleName}}"
  stack_name    = "{{.TargetStackName}}"
  boundary_name    = "iam-role-boundary-${var.account_name}"
  signInUrl    = "https://signin.aws.amazon.com/federation"
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

# -------------------------
# Trust Policy
# -------------------------
data "aws_iam_policy_document" "ops_role_trust_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [var.aws_login_user]
    }
  }
}

# -------------------------
# Main ops_role_policy (CFN + IAM access)
# -------------------------
data "aws_iam_policy_document" "ops_role_policy" {

  # CloudFormation stack mgmt
  statement {
    sid = "AllowManageSpecificStack"

    actions = [
      "cloudformation:CreateStack",
      "cloudformation:UpdateStack",
      "cloudformation:DeleteStack",
      "cloudformation:DescribeStacks",
      "cloudformation:DescribeStackEvents"
    ]

    resources = [
      "arn:aws:cloudformation:${data.aws_region.current.region}:${data.aws_caller_identity.current.account_id}:stack/${local.stack_name}"
    ]
  }

  # Allow IAM actions only when invoked via CloudFormation
  statement {
    sid = "AllowFullIAMViaCloudFormation"

    effect = "Allow"

    actions = [
      "iam:*"
    ]

    resources = ["*"]

    condition {
      test     = "ForAnyValue:StringEquals"
      variable = "aws:CalledVia"
      values   = ["cloudformation.amazonaws.com"]
    }
  }

  # Allow PassRole for CFN-created roles
  statement {
    sid = "AllowPassRole"
    actions = ["iam:PassRole"]
    resources = ["*"]
  }
}

# -------------------------
# Role & Policy Attachment
# -------------------------
resource "aws_iam_role" "ops_role" {
  name               = local.ops_role_name
  description        = "Ops role for AWS Login bootstrap"
  assume_role_policy = data.aws_iam_policy_document.ops_role_trust_policy.json
}

resource "aws_iam_policy" "ops_role_policy" {
  name   = "ops_role_policy-${var.account_name}"
  policy = data.aws_iam_policy_document.ops_role_policy.json
}

resource "aws_iam_policy_attachment" "ops_role_attach_policy" {
  name       = "ops-role-policy-attachment"
  roles      = [aws_iam_role.ops_role.name]
  policy_arn = aws_iam_policy.ops_role_policy.arn
}`))

func (a *accountService) BootstrapTemplate(ctx context.Context, accountName string, terraform bool) (string, error) {
	_, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return "", fmt.Errorf("accountService.BootstrapTemplate: storage.GetAccount: %w", err)
	}
	_, arn, err := a.aws.WhoAmI(ctx)
	if err != nil {
		return "", fmt.Errorf("accountService.BootstrapTemplate: aws.WhoAmi: %w", err)
	}
	tmpl := bootstrapStackTemplateCfn
	if terraform {
		tmpl = bootstrapStackTemplateTerraform
	}
	return templateExecuteToString(tmpl,
		struct {
			TargetStackName string
			Principal       string
			OpsRoleName     string
			AccountName     string
		}{
			TargetStackName: aws.StackName.Value(accountName),
			Principal:       arn,
			OpsRoleName:     aws.OpsRole.Value(accountName),
			AccountName:     accountName,
		})
}
