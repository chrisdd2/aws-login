package storage

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

type StorageService struct {
	Storage
}

func (s *StorageService) CreateAccount(ctx context.Context, acc Account) (Account, error) {
	if acc.FriendlyName == "" || !ValidateAWSAccountID(acc.AwsAccountId) {
		return acc, ErrInvalidAccountDetails
	}
	_, err := s.GetAccountByAwsAccountId(ctx, acc.AwsAccountId)
	if err != ErrAccountNotFound {
		return acc, ErrAccountAlreadyExists
	}
	acc, err = s.PutAccount(ctx, acc, false)
	if err != nil {
		return acc, err
	}
	// add default roles
	dev, err := s.PutRole(ctx, GetDeveloperRole(), false)
	if err != nil {
		return acc, err
	}
	ro, err := s.PutRole(ctx, GetReadOnlyRole(), false)
	if err != nil {
		return acc, err
	}
	// attach to account
	return acc, errors.Join(s.PutRoleAssociation(ctx, acc.Id, dev.Id, false), s.PutRoleAssociation(ctx, acc.Id, ro.Id, false))
}

func (s *StorageService) HasPermission(ctx context.Context, id PermissionId, value string) (bool, error) {
	// check if super user
	usr, err := s.GetUserById(ctx, id.UserId)
	if err != nil {
		return false, fmt.Errorf("HasPermission [storage.GetUserById %w]", err)
	}
	// super boys are allowed
	if usr.Superuser {
		return true, nil
	}
	res, err := s.Storage.ListPermissions(ctx, id.UserId, id.AccountId, id.Type, id.Scope, nil)
	if err != nil {
		return false, fmt.Errorf("HasPermission [storage.ListPermissions %w]", err)
	}
	if len(res.Permissions) == 0 {
		return false, nil
	}
	// empty means if has any permission
	if value == "" {
		return true, nil
	}
	// check if value present in permissions
	return slices.Contains(res.Permissions[0].Value, value), nil
}

func (s *StorageService) UpdatePermissionValue(ctx context.Context, updaterUserId string, id PermissionId, value []string, remove bool) error {
	has, err := s.HasPermission(ctx, PermissionId{UserId: updaterUserId, AccountId: id.AccountId, Type: id.Type, Scope: id.Scope}, PermissionGrant)
	if err != nil {
		return fmt.Errorf("UpdatePermissionValue [storage.HasPermission %w]", err)
	}
	if !has {
		return ErrNoPermission
	}

	res, err := s.ListPermissions(ctx, id.UserId, id.AccountId, id.Type, id.Scope, nil)
	if err != nil {
		return fmt.Errorf("UpdatePermissionValue [storage.ListPermissions %w]", err)
	}
	perm := Permission{PermissionId: id}
	if len(res.Permissions) > 0 {
		perm = res.Permissions[0]
	}
	if remove {
		perm.Value = slices.DeleteFunc(perm.Value, func(v string) bool {
			return slices.Contains(value, v)
		})
	} else {
		// add unique values
		perm.Value = mergeArray(perm.Value, value)
	}
	// if there are no permission, delete it instead
	shouldDelete := len(perm.Value) == 0
	if err := s.PutPermission(ctx, perm, shouldDelete); err != nil {
		return fmt.Errorf("UpdatePermissionValue [storage.PutPermission %w]", err)
	}
	return nil
}

func mergeArray(a []string, b []string) []string {
	res := make([]string, 0, len(a)+len(b))
	res = append(res, a...)
	for _, v := range b {
		if !slices.Contains(a, v) {
			res = append(res, v)
		}
	}
	return res
}
