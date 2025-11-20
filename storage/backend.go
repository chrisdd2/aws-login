package storage

import "io"

type StorageBackend interface {
	AccountPermissionService
	RolePermissionService
	UserService
	AccountService
	RoleService

	io.Closer
}
