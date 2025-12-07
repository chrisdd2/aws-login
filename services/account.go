package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
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
	StackExists bool
	NeedsUpdate bool
}

type AccountService interface {
	Deploy(ctx context.Context, userId string, accountId string) error
	DeploymentStatus(ctx context.Context, accountId string) (DeploymentStatus, error)
	StackUpdates(ctx context.Context, accountName string, stackId string) ([]aws.StackEvent, error)
	DestroyStack(ctx context.Context, accountName string) (string, error)
	GetFromAccountName(ctx context.Context, name string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)
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
	awsAccountId := strconv.Itoa(account.AwsAccountId)
	if err != nil {
		return err
	}
	return a.aws.DeployStack(ctx, awsAccountId, aws.StackName, templateString, nil, map[string]string{stackHash: h})
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
	status := DeploymentStatus{}
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

	tags, err := a.aws.StackTags(ctx, strconv.Itoa(acc.AwsAccountId), aws.StackName, nil, true)
	if err == aws.ErrStackNotExist {
		status.StackExists = false
		return status, nil
	}
	if err != nil {
		return status, fmt.Errorf("aws.StackTags: %w", err)
	}
	status.StackExists = true
	stackHash := tags[stackHash]
	log.Printf("currentHash=%s\nstackHash%s\n", currentHash, stackHash)
	status.NeedsUpdate = stackHash == currentHash
	return status, nil
}
func (a *accountService) StackUpdates(ctx context.Context, accountName string, stackId string) ([]aws.StackEvent, error) {
	acc, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return nil, fmt.Errorf("accountService.StackUpdates: storage.GetAccount: %w", err)
	}
	if stackId == "" {
		stackId = aws.StackName
	}
	events, err := a.aws.LatestStackEvents(ctx, acc.AccountId(), stackId)
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
	stackId, err := a.aws.DestroyStack(ctx, acc.AccountId(), aws.StackName)
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
