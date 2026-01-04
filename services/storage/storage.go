package storage

import (
	"context"
	"errors"

	"github.com/chrisdd2/aws-login/appconfig"
)

var ErrUserNotFound = errors.New("UserNotFound")

type Reloadable interface {
	Reload(ctx context.Context) error
}

type Printable interface {
	Display(ctx context.Context) (string, error)
}

type Writable interface {
	PutRole(ctx context.Context, r *appconfig.Role, delete bool) error
	PutAccount(ctx context.Context, r *appconfig.Account, delete bool) error
	PutUserRoleAttachment(ctx context.Context, username string, a appconfig.RoleUserAttachment, delete bool) error
	PutPolicy(ctx context.Context, policyName string, policyDocument string) error
}

type Storage interface {
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)

	ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error)
	GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error)

	GetRole(ctx context.Context, name string) (*appconfig.Role, error)
	GetUser(ctx context.Context, name string) (*appconfig.User, error)
	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)
}
