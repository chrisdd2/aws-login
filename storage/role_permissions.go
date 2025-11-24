package storage

import (
	"context"
	"iter"
)

type RolePermissionType int

const (
	RolePermissionLogin = RolePermissionType(iota)
	RolePermissionCredential
	RolePermissionGrant
)

type RolePermission struct {
	AccountId string
	UserId    string
	RoleId    string
	Type      RolePermissionType
}

type RolePermissionService interface {
	PutRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType, delete bool) (*RolePermission, error)
	HasRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType) (bool, error)
	ListRolePermissions(ctx context.Context, userId string, accountId string, token *string) (perms iter.Seq[*RolePermission], nextToken *string, err error)
}
