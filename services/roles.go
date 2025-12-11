package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/aws"
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
	UserPermissions(ctx context.Context, username string, roleName string, accountName string) ([]*appconfig.RoleAttachment, error)
	RolesForAccount(ctx context.Context, accountName string) ([]*appconfig.RoleAttachment, error)
	Console(ctx context.Context, accountName string, roleName, sessionName string) (string, error)
	Credentials(ctx context.Context, accountName string, roleName, sessionName string) (AwsCredentials, error)
}

type rolesService struct {
	storage Storage
	aws     aws.AwsApiCaller
}

func NewRoleService(store Storage, aws aws.AwsApiCaller) RolesService {
	return &rolesService{store, aws}
}

func (r *rolesService) RolesForAccount(ctx context.Context, accountName string) ([]*appconfig.RoleAttachment, error) {
	roles, err := r.storage.ListRolesForAccount(ctx, accountName)
	if err != nil {
		return nil, err
	}
	ret := make([]*appconfig.RoleAttachment, 0, len(roles))
	for _, role := range roles {
		for _, associated := range role.AssociatedAccounts {
			ret = append(ret, &appconfig.RoleAttachment{
				RoleName:    role.Name,
				AccountName: associated,
				Permissions: []string{"credentials", "console"},
			})
		}
	}
	return ret, nil
}
func (r *rolesService) UserPermissions(ctx context.Context, username string, roleName string, accountName string) ([]*appconfig.RoleAttachment, error) {
	return r.storage.ListRolePermissions(ctx, username, roleName, accountName)
}
func (r *rolesService) Console(ctx context.Context, accountName string, roleName, sessionName string) (string, error) {
	role, err := r.storage.GetRole(ctx, roleName)
	if err != nil {
		return "", fmt.Errorf("storage.GetRole: %w", err)
	}
	if !slices.Contains(role.AssociatedAccounts, accountName) {
		return "", errors.New("account not associated with role")
	}
	acc, err := r.storage.GetAccount(ctx, accountName)
	if err != nil {
		return "", fmt.Errorf("storage.GetAccount: %w", err)
	}
	arn := role.Arn(acc.AwsAccountId)
	url, err := r.aws.GenerateSigninUrl(ctx, arn, sessionName, "https://console.aws.amazon.com/")
	if err != nil {
		return "", fmt.Errorf("aws.GenerateSigninUrl: %w", err)
	}
	return url, nil
}

func (r *rolesService) Credentials(ctx context.Context, accountName string, roleName, sessionName string) (AwsCredentials, error) {
	role, err := r.storage.GetRole(ctx, roleName)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("storage.GetRole: %w", err)
	}
	if !slices.Contains(role.AssociatedAccounts, accountName) {
		return AwsCredentials{}, errors.New("account not associated with role")
	}
	acc, err := r.storage.GetAccount(ctx, accountName)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("storage.GetAccount: %w", err)
	}
	arn := role.Arn(acc.AwsAccountId)
	accessKeyId, secretAccessKey, sessionToken, err := r.aws.GetCredentials(ctx, arn, sessionName)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("aws.GenerateSigninUrl: %w", err)
	}
	return AwsCredentials{AccessKeyId: accessKeyId, SecretAccessKey: secretAccessKey, SessionToken: sessionToken}, nil
}
