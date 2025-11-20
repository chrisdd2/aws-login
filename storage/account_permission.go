package storage

import (
	"context"
	"iter"
)

type AccountPermissionType int

const (
	AccountPermissionBootstrap = RolePermissionType(iota)
	AccountPermissionStatus
)

type AccountPermission struct {
	AccountId string
	UserId    string
	Type      AccountPermissionType
}

type AccountPermissionService interface {
	PutAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType, delete bool) error
	HasAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType) (bool, error)
	ListAccountPermissions(ctx context.Context, userId string, accountId string) (iter.Seq[*AccountPermission], error)
}
