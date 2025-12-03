package services

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/chrisdd2/aws-login/storage"
	sg "github.com/chrisdd2/aws-login/storage"
)

type RolesService interface {
	UserPermissions(ctx context.Context, userId string, accountId string) ([]*ExtendedPermission, error)
}

type rolesService struct {
	storage storage.Service
}

type ExtendedPermission struct {
	*sg.RolePermission
	*sg.Account
	*sg.Role
}

func (r *rolesService) UserPermissions(ctx context.Context, userId string, accountId string) ([]*ExtendedPermission, error) {
	token := (*string)(nil)
	accounts := map[string]*sg.Account{}
	roles := map[string]*sg.Role{}
	perms := []*ExtendedPermission{}
	for {
		seq, nextToken, err := r.storage.ListRolePermissions(ctx, accountId, userId, token)
		if err != nil {
			return nil, fmt.Errorf("storage.ListRolePermission: %w", err)
		}
		for perm := range seq {
			perms = append(perms, &ExtendedPermission{
				RolePermission: perm,
			})
			accounts[perm.AccountId] = nil
			roles[perm.RoleId] = nil
		}
		if nextToken == nil {
			break
		}
		token = nextToken
	}
	rolesSlice, err := r.storage.GetRoles(ctx, slices.Collect(maps.Keys(roles))...)
	if err != nil {
		return nil, fmt.Errorf("storage.GetRoles: %w", err)
	}
	accountsSlice, err := r.storage.GetAccounts(ctx, slices.Collect(maps.Keys(accounts))...)
	if err != nil {
		return nil, fmt.Errorf("storage.GetAccounts: %w", err)
	}
	for _, role := range rolesSlice {
		roles[role.Id] = role
	}
	for _, acc := range accountsSlice {
		accounts[acc.Id] = acc
	}
	for _, perm := range perms {
		perm.Account = accounts[perm.RolePermission.AccountId]
		perm.Role = roles[perm.RolePermission.RoleId]
	}
	return perms, nil
}
