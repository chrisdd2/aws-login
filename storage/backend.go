package storage

import (
	"context"
	"io"
	"iter"
	"time"
)

type Service interface {
	AccountPermissionService
	RolePermissionService
	UserService
	AccountService
	RoleService

	io.Closer
}
type RolePermissionService interface {
	PutRolePermission(ctx context.Context, p *RolePermission, del bool) (*RolePermission, error)
	HasRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType) (bool, error)
	ListRolePermissions(ctx context.Context, userId string, accountId string, token *string) (perms iter.Seq[*RolePermission], nextToken *string, err error)
}
type RoleService interface {
	GetRole(ctx context.Context, id string) (*Role, error)
	GetRoles(ctx context.Context, id ...string) ([]*Role, error)
	PutRole(ctx context.Context, role *Role, delete bool) (*Role, error)
	ListRoles(ctx context.Context, accountId string, token *string) (roles iter.Seq[*Role], nextToken *string, err error)
}

type UserService interface {
	GetUsers(ctx context.Context, id ...string) ([]*User, error)
	GetUserByName(ctx context.Context, name string) (*User, error)
	PutUser(ctx context.Context, user *User, delete bool) (*User, error)
	ListUsers(ctx context.Context, token *string) (users iter.Seq[*User], nextToken *string, err error)
}
type AccountService interface {
	GetAccount(ctx context.Context, id string) (*Account, error)
	GetAccounts(ctx context.Context, id ...string) ([]*Account, error)
	GetAccountByAwsAccountId(ctx context.Context, accountId int) (*Account, error)
	PutAccount(ctx context.Context, acc *Account, delete bool) (*Account, error)
	ListAccounts(ctx context.Context, token *string) (accounts iter.Seq[*Account], nextToken *string, err error)
}
type AccountPermissionService interface {
	PutAccountPermission(ctx context.Context, acc *AccountPermission, delete bool) (*AccountPermission, error)
	HasAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType) (bool, error)
	ListAccountPermissions(ctx context.Context, userId string, accountId string, token *string) (perms iter.Seq[*AccountPermission], nextToken *string, err error)
}

// defaults
func DeveloperRoleDefinition(accountId string, roleName string) *Role {
	if roleName == "" {
		roleName = DeveloperRole
	}
	return &Role{
		Name:               roleName,
		AccountId:          accountId,
		MaxSessionDuration: time.Hour * 8,
		Enabled:            true,
		ManagedPolicies: []string{
			"arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}
func ReadOnlyRoleDefinition(accountId string, roleName string) *Role {
	if roleName == "" {
		roleName = ReadOnlyRole
	}
	return &Role{
		Name:               roleName,
		AccountId:          accountId,
		MaxSessionDuration: time.Hour * 8,
		Enabled:            true,
		ManagedPolicies: []string{
			"arn:aws:iam::aws:policy/ReadOnlyAccess",
		},
	}
}

const (
	DeveloperRole = "developer-role-" + UniqueId
	ReadOnlyRole  = "read-only-role-" + UniqueId
	UniqueId      = "8db7bc11-acf5-4c7a-be46-967f44e33028"
)
