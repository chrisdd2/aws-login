package storage

import (
	"context"
	"errors"

	"github.com/chrisdd2/aws-login/appconfig"
)

var ErrUserNotFound = errors.New("UserNotFound")

type Storage interface {
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)

	ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]*appconfig.RoleUserAttachment, error)
	GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error)

	GetRole(ctx context.Context, name string) (*appconfig.Role, error)
	GetUser(ctx context.Context, name string) (*appconfig.User, error)
	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)

	Reload(ctx context.Context) error
	PrettyPrint(ctx context.Context) (string, error)
}
