package services

import (
	"context"

	"github.com/chrisdd2/aws-login/appconfig"
)

type RolesService interface {
	UserPermissions(ctx context.Context, username string, accountName string) ([]*appconfig.RoleAttachment, error)
}

type rolesService struct {
	storage Storage
}

func NewRoleService(store Storage) RolesService {
	return &rolesService{store}
}

func (r *rolesService) UserPermissions(ctx context.Context, username string, accountName string) ([]*appconfig.RoleAttachment, error) {
	return r.storage.ListRolePermissions(ctx, username, accountName)
}
