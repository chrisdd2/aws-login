package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"maps"
	"slices"

	"github.com/chrisdd2/aws-login/internal/aws"
	"github.com/chrisdd2/aws-login/store"
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
		return fmt.Sprintf("$env:AWS_ACCESS_KEY_ID=\"%s\"\n$env:AWS_SECRET_ACCESS_KEY=\"=%s\"\n$env:AWS_SESSION_TOKEN=\"%s\"", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	case "linux":
		return fmt.Sprintf("export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\nexport AWS_SESSION_TOKEN=%s", c.AccessKeyId, c.SecretAccessKey, c.SessionToken)
	default:
		// just json
		buf, _ := json.Marshal(c)
		return string(buf)
	}
}

type UserRolePermission struct {
	AccountId   string
	AccountName string
	RoleName    string
	Permissions []string
}

type RolesService interface {
	HasPermission(ctx context.Context, username string, roleName string, accountName string, permissions string) (bool, error)
	ListRoles(ctx context.Context, username string) (iter.Seq[UserRolePermission], error)
	Console(ctx context.Context, accountName string, roleName, username string) (string, error)
	Credentials(ctx context.Context, accountName string, roleName, username string) (AwsCredentials, error)
}

type rolesService struct {
	st  store.Store
	aws aws.AwsApiCaller
}

func NewRoleService(st store.Store, aws aws.AwsApiCaller) RolesService {
	return &rolesService{st, aws}
}

func (r *rolesService) HasPermission(ctx context.Context, username, roleName, accountName, permission string) (bool, error) {
	role, err := store.GetResource(ctx, r.st, store.ResourceTypeRole, roleName)
	if err != nil {
		return false, err
	}
	account, err := store.GetResource(ctx, r.st, store.ResourceTypeAccount, accountName)
	if err != nil {
		return false, err
	}
	usr, err := store.GetResource(ctx, r.st, store.ResourceTypeUser, username)
	if err != nil {
		return false, err
	}
	if role.Disabled || account.Disabled || usr.Disabled {
		return false, err
	}
	atts, err := r.st.GetResourceAttachments(ctx, store.AccountAttachmentRole, roleName, accountName)
	if err != nil {
		return false, store.ErrDisabled
	}
	if len(atts) == 0 {
		return false, store.ErrResourceNotFound
	}
	perm, err := store.GetUserPermission(ctx, r.st, store.UserPermissionRole, username, roleName, accountName)
	if err != nil {
		return false, err
	}
	return perm.Permissions[permission] != "", nil
}
func (r *rolesService) ListRoles(ctx context.Context, username string) (iter.Seq[UserRolePermission], error) {
	// figure out all the attachments for a user
	_, err := store.GetUserPermission(ctx, r.st, store.UserPermissionSuperUser, username, "", "")
	super := err == nil
	if super {
		perms, err := r.st.GetResourceAttachments(ctx, store.AccountAttachmentRole, "", "")
		if err != nil {
			return nil, err
		}
		return func(yield func(UserRolePermission) bool) {
			for _, p := range perms {
				if !yield(UserRolePermission{
					AccountId:   p.Metadata["aws_account_id"],
					AccountName: p.TargetResourceId,
					RoleName:    p.ResourceId,
					Permissions: store.RolePermissionAll,
				}) {
					break
				}
			}
		}, nil
	}
	perms, err := r.st.GetUserPermission(ctx, store.UserPermissionRole, username, "", "")
	if err != nil {
		return nil, err
	}
	return func(yield func(UserRolePermission) bool) {
		for _, p := range perms {
			if !yield(UserRolePermission{
				AccountId:   p.Metadata["aws_account_id"],
				AccountName: p.AccountId,
				RoleName:    p.ResourceId,
				Permissions: slices.Collect(maps.Keys(p.Permissions)),
			}) {
				break
			}
		}
	}, nil
}
func (r *rolesService) Console(ctx context.Context, accountName string, roleName, username string) (string, error) {
	hasPerm, err := r.HasPermission(ctx, username, roleName, accountName, store.RolePermissionConsole)
	if err != nil {
		return "", fmt.Errorf("r.HasPermission: %w", err)
	}
	if !hasPerm {
		return "", ErrRoleUnauthorized
	}
	acc, err := store.GetResource(ctx, r.st, store.ResourceTypeAccount, accountName)
	if err != nil {
		return "", err
	}
	arn := roleArn(roleName, acc.Metadata["aws_account_id"])
	url, err := r.aws.GenerateSigninUrl(ctx, arn, username, "https://console.aws.amazon.com/")
	if err != nil {
		return "", fmt.Errorf("aws.GenerateSigninUrl: %w", err)
	}
	return url, nil
}

func (r *rolesService) Credentials(ctx context.Context, accountName string, roleName, username string) (AwsCredentials, error) {
	hasPerm, err := r.HasPermission(ctx, username, roleName, accountName, store.RolePermissionCredentials)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("r.HasPermission: %w", err)
	}
	if !hasPerm {
		return AwsCredentials{}, ErrRoleUnauthorized
	}
	acc, err := store.GetResource(ctx, r.st, store.ResourceTypeAccount, accountName)
	if err != nil {
		return AwsCredentials{}, err
	}
	arn := roleArn(roleName, acc.Metadata["aws_account_id"])
	accessKeyId, secretAccessKey, sessionToken, err := r.aws.GetCredentials(ctx, arn, username)
	if err != nil {
		return AwsCredentials{}, fmt.Errorf("aws.GenerateSigninUrl: %w", err)
	}
	return AwsCredentials{AccessKeyId: accessKeyId, SecretAccessKey: secretAccessKey, SessionToken: sessionToken}, nil
}

func roleArn(roleName string, accountId string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
}
