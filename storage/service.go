package storage

import (
	"context"
	"errors"
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
