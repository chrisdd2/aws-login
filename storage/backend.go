package storage

import "io"

type Service interface {
	AccountPermissionService
	RolePermissionService
	UserService
	AccountService
	RoleService

	io.Closer
}
