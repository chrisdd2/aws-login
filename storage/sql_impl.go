package storage

import (
	"context"
	"iter"
)

type sqlBackend struct {
}

func NewSqlBackend(fileName string) (Service, error) {
	return &sqlBackend{}, nil
}

func (s *sqlBackend) GetUsers(ctx context.Context, id ...string) ([]*User, error) {
}

func (s *sqlBackend) GetUserByName(ctx context.Context, name string) (*User, error) {
}
func (s *sqlBackend) PutUser(ctx context.Context, user *User, del bool) (*User, error) {
}
func (s *sqlBackend) ListUsers(ctx context.Context, nextToken *string) (iter.Seq[*User], *string, error) {
}

func (s *sqlBackend) GetAccount(ctx context.Context, id ...string) ([]*Account, error) {
}

func (s *sqlBackend) GetAccountByAwsAccountId(ctx context.Context, accountId int) (*Account, error) {
}
func (s *sqlBackend) PutAccount(ctx context.Context, account *Account, del bool) (*Account, error) {
}

func (s *sqlBackend) ListAccounts(ctx context.Context, nextToken *string) (iter.Seq[*Account], *string, error) {
}

func (s *sqlBackend) PutAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType, delete bool) error {
}
func (s *sqlBackend) HasAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType) (bool, error) {
}
func (s *sqlBackend) ListAccountPermissions(ctx context.Context, userId string, accountId string, nextToken *string) (iter.Seq[*AccountPermission], *string, error) {
}

func (s *sqlBackend) PutRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType, del bool) (*RolePermission, error) {
}
func (s *sqlBackend) HasRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType) (bool, error) {
}
func (s *sqlBackend) ListRolePermissions(ctx context.Context, userId string, accountId string, nextToken *string) (iter.Seq[*RolePermission], *string, error) {
}

func (s *sqlBackend) GetRole(ctx context.Context, id ...string) ([]*Role, error) {
}
func (s *sqlBackend) PutRole(ctx context.Context, role *Role, del bool) (*Role, error) {
}
func (s *sqlBackend) ListRoles(ctx context.Context, accountId string, nextToken *string) (iter.Seq[*Role], *string, error) {
}
