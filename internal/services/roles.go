package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"slices"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/aws"
	"github.com/chrisdd2/aws-login/internal/services/storage"
)

var (
	ErrAccountDisabled   = errors.New("account is disabled")
	ErrRoleDisabled      = errors.New("role is disabled")
	ErrRoleUnauthorized  = errors.New("no permission to use this role")
	ErrRoleNotAssociated = errors.New("account not associated with role")
)

type AwsCredentials struct {
	AccessKeyId     string `json:"aws_access_key_id,omitempty"`
	SecretAccessKey string `json:"aws_secret_access_key,omitempty"`
	SessionToken    string `json:"aws_session_token,omitempty"`
}

func (c AwsCredentials) Format(t string) string {
	switch t {
	case "cmd":
		return fmt.Sprintf("set AWS_ACCESS_KEY_ID=%s\nset AWS_SECRET_ACCESS_KEY=%s\nset AWS_SESSION_TOKEN=%s", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	case "powershell":
		return fmt.Sprintf("$env:AWS_ACCESS_KEY_ID=\"%s\"\n$env:AWS_SECRET_ACCESS_KEY=\"=%s\"\n$env:AWS_ACCESS_KEY_ID=\"%s\"", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	case "linux":
		return fmt.Sprintf("export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\nexport AWS_SESSION_TOKEN=%s", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	default:
		// just json
		buf, _ := json.Marshal(c)
		return string(buf)
	}
}

type RolesService interface {
	UserPermissions(ctx context.Context, username string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error)
	Console(ctx context.Context, accountName string, roleName, username string) (string, error)
	Credentials(ctx context.Context, accountName string, roleName, username string) (AwsCredentials, error)
}

type rolesService struct {
	storage storage.Storage
	aws     aws.AwsApiCaller
	ev      storage.Eventer
}

func NewRoleService(store storage.Storage, aws aws.AwsApiCaller, ev storage.Eventer) RolesService {
	return &rolesService{store, aws, ev}
}

func (r *rolesService) UserPermissions(ctx context.Context, username string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error) {
	return r.storage.ListRolePermissions(ctx, username, roleName, accountName)
}
func (r *rolesService) Console(ctx context.Context, accountName string, roleName, username string) (string, error) {
	role, err := r.storage.GetRole(ctx, roleName)
	if err != nil {
		return "", fmt.Errorf("storage.GetRole: %w", err)
	}
	if role.Disabled {
		return "", ErrRoleDisabled
	}
	acc, err := r.storage.GetAccount(ctx, accountName)
	if err != nil {
		return "", fmt.Errorf("storage.GetAccount: %w", err)
	}
	if acc.Disabled {
		return "", ErrAccountDisabled
	}
	attachments, err := r.storage.ListRoleAccountAttachments(ctx, roleName, accountName)
	if err != nil {
		return "", fmt.Errorf("storage.ListRoleAccountAttachments: %w", err)
	}
	if !slices.ContainsFunc(attachments, func(at appconfig.RoleAccountAttachment) bool {
		return roleName == at.RoleName
	}) {
		return "", ErrRoleNotAssociated
	}
	// auth check
	perms, err := r.UserPermissions(ctx, username, roleName, accountName)
	if err != nil {
		return "", err
	}
	if len(perms) == 0 || !slices.Contains(perms[0].Permissions, appconfig.RolePermissionConsole) {
		return "", ErrRoleUnauthorized
	}

	arn := roleArn(roleName, acc.AwsAccountId)
	url, err := r.aws.GenerateSigninUrl(ctx, arn, username, "https://console.aws.amazon.com/")
	if err != nil {
		return "", fmt.Errorf("aws.GenerateSigninUrl: %w", err)
	}
	// publish an event
	r.ev.Publish(ctx, "console_login", map[string]string{"username": username, "account_name": accountName, "role_name": roleName})
	return url, nil
}

func (r *rolesService) Credentials(ctx context.Context, accountName string, roleName, username string) (AwsCredentials, error) {
	role, err := r.storage.GetRole(ctx, roleName)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("storage.GetRole: %w", err)
	}
	if role.Disabled {
		return AwsCredentials{}, ErrRoleDisabled
	}
	acc, err := r.storage.GetAccount(ctx, accountName)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("storage.GetAccount: %w", err)
	}
	if acc.Disabled {
		return AwsCredentials{}, ErrAccountDisabled
	}
	attachments, err := r.storage.ListRoleAccountAttachments(ctx, roleName, accountName)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("storage.ListRoleAccountAttachments: %w", err)
	}
	log.Println(attachments)
	if !slices.ContainsFunc(attachments, func(at appconfig.RoleAccountAttachment) bool {
		return roleName == at.RoleName
	}) {
		return AwsCredentials{}, ErrRoleNotAssociated
	}

	// auth check
	perms, err := r.UserPermissions(ctx, username, roleName, accountName)
	if err != nil {
		return AwsCredentials{}, err
	}
	if len(perms) == 0 || !slices.Contains(perms[0].Permissions, appconfig.RolePermissionCredentials) {
		return AwsCredentials{}, ErrRoleUnauthorized
	}

	arn := roleArn(roleName, acc.AwsAccountId)
	accessKeyId, secretAccessKey, sessionToken, err := r.aws.GetCredentials(ctx, arn, username)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("aws.GenerateSigninUrl: %w", err)
	}
	// publish an event
	r.ev.Publish(ctx, "credentials_login", map[string]string{"username": username, "account_name": accountName, "role_name": roleName})
	return AwsCredentials{AccessKeyId: accessKeyId, SecretAccessKey: secretAccessKey, SessionToken: sessionToken}, nil
}

func roleArn(roleName string, accountId string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
}
