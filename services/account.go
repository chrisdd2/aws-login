package services

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	sg "github.com/chrisdd2/aws-login/storage"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

type AccountService interface {
	Create(ctx context.Context, awsAccountId int, name string, tags map[string]string) (*sg.Account, error)
	Save(ctx context.Context, acc *sg.Account) error
	Deploy(ctx context.Context, userId string, accountId string) error
}

type accountService struct {
	storage storage.Service
	aws     aws.AwsApiCaller
}

var baseStackTemplate = template.Must(template.New("base-stack").Parse(
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

	hasPerm, err := a.storage.HasAccountPermission(ctx, userId, accountId, storage.AccountPermissionBootstrap)
	if !(user.Superuser || hasPerm) {
		return errors.New("no permission for this action")
	}

	// gather up all the roles that need to be deployed as part of the stack
	type CfnRole struct {
		LogicalName        string
		RoleName           string
		ManagedPolicies    []string
		Policies           map[string]string
		MaxSessionDuration string
	}

	roles := make([]CfnRole, 0, 2)
	var token *string
	for {
		iter, nextToken, err := a.storage.ListRoles(ctx, accountId, token)
		if err != nil {
			return err
		}
		for item := range iter {
			roles = append(roles, CfnRole{
				LogicalName:        roleLogicalName(item.Name),
				RoleName:           item.Name,
				ManagedPolicies:    item.ManagedPolicies,
				Policies:           item.Policies,
				MaxSessionDuration: maxSessionDuration(item.MaxSessionDuration),
			})
		}
		if nextToken == nil {
			break
		}
		token = nextToken
	}
	templateString, err := templateExecuteToString(baseStackTemplate, struct{ Roles []CfnRole }{Roles: roles})
	if err != nil {
		return err
	}

	// Deploy the stack
	account, err := a.storage.GetAccount(ctx, accountId)
	if err != nil {
		return err
	}

	err = a.aws.DeployStack(ctx, account.AccountIdStr(), aws.StackName, templateString, nil)
	if err != nil {
		return err
	}
	// update sync time for logging purposes
	account.SyncTime = time.Now().UTC()
	account.SyncBy = userId
	_, err = a.storage.PutAccount(ctx, account, false)
	return err
}

func (a *accountService) Save(ctx context.Context, acc *sg.Account) error {
	_, err := a.storage.PutAccount(ctx, acc, false)
	if err != nil {
		return err
	}
	return nil
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

var ErrInvalidAccountDetails error = errors.New("invalid account details")
var ErrAccountAlreadyExists error = errors.New("account already exists")

func (a *accountService) Create(ctx context.Context, userId string, acc *sg.Account) (*sg.Account, error) {

	// Permission check
	user, err := a.storage.GetUser(ctx, userId)
	if err != nil {
		return nil, err
	}
	if !user.Superuser {
		return nil, errors.New("only superusers can create accounts")
	}

	// Account validation
	if acc.Name == "" || ValidateAWSAccountID(acc.AwsAccountId) {
		return nil, ErrInvalidAccountDetails
	}
	_, err = a.storage.GetAccountByAwsAccountId(ctx, acc.AwsAccountId)
	if err != sg.ErrAccountNotFound {
		return nil, ErrAccountAlreadyExists
	}

	// Commit account
	acc.UpdateBy = userId
	acc.UpdateTime = time.Now().UTC()
	acc, err = a.storage.PutAccount(ctx, acc, false)
	if err != nil {
		return nil, err
	}

	// Add the default roles
	_, err = a.storage.PutRole(ctx, sg.DeveloperRoleDefinition(acc.Id, sg.DeveloperRole), false)
	if err != nil {
		return nil, err
	}
	_, err = a.storage.PutRole(ctx, sg.ReadOnlyRoleDefinition(acc.Id, sg.ReadOnlyRole), false)
	if err != nil {
		return nil, err
	}
	return acc, nil
}
