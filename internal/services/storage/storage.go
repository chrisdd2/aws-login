package storage

import (
	"context"
	"errors"

	"github.com/chrisdd2/aws-login/appconfig"
)

var (
	ErrUserNotFound    = errors.New("UserNotFound")
	ErrPolicyNotFound  = errors.New("PolicyNotFound")
	ErrAccountNotFound = errors.New("AccountNotFound")
	ErrRoleNotFound    = errors.New("RoleNotFound")
)

type Reloadable interface {
	Reload(ctx context.Context) error
}

type Printable interface {
	Display(ctx context.Context) (*InMemoryStore, error)
}

type Writeable interface {
	PutUser(ctx context.Context, u *appconfig.User) error
	PutAccount(ctx context.Context, a *appconfig.Account) error
	PutPolicy(ctx context.Context, p *appconfig.Policy) error

	PutRole(ctx context.Context, r *appconfig.Role) error
	PutRoleAccountAttachment(ctx context.Context, r *appconfig.RoleAccountAttachment) error
	PutRolePolicyAttachment(ctx context.Context, r *appconfig.RolePolicyAttachment) error
	PutRoleUserAttachment(ctx context.Context, r *appconfig.RoleUserAttachment) error
}

type Readable interface {
	GetRole(ctx context.Context, name string) (*appconfig.Role, error)
	GetUser(ctx context.Context, name string) (*appconfig.User, error)
	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
	GetPolicy(ctx context.Context, id string) (*appconfig.Policy, error)

	ListAccounts(ctx context.Context) ([]appconfig.Account, error)
	ListUsers(ctx context.Context) ([]string, error)
	ListPolicies(ctx context.Context) ([]string, error)
	ListRoles(ctx context.Context) ([]string, error)
	ListRoleAccountAttachments(ctx context.Context, roleName string, accountName string) ([]appconfig.RoleAccountAttachment, error)
	ListRoleUserAttachments(ctx context.Context, username string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error)
	ListRolePolicyAttachments(ctx context.Context, roleName string) ([]appconfig.RolePolicyAttachment, error)
}

type Storage interface {
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)
	ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error)
	Readable
	Eventer
}

type Eventer interface {
	Publish(ctx context.Context, eventType string, metadata map[string]string) error
}

type InMemoryStore struct {
	Users                  []appconfig.User                  `json:"users,omitempty"`
	Accounts               []appconfig.Account               `json:"accounts,omitempty"`
	Roles                  []appconfig.Role                  `json:"roles,omitempty"`
	Policies               []appconfig.Policy                `json:"policies,omitempty"`
	RolePolicyAttachments  []appconfig.RolePolicyAttachment  `json:"role_policy_attachments,omitempty"`
	RoleUserAttachments    []appconfig.RoleUserAttachment    `json:"role_user_attachments,omitempty"`
	RoleAccountAttachments []appconfig.RoleAccountAttachment `json:"role_account_attachments,omitempty"`
}

func (s *InMemoryStore) Display(ctx context.Context) (*InMemoryStore, error) {
	return s, nil
}
