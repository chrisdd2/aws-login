package storage

import (
	"context"

	"github.com/chrisdd2/aws-login/aws"
)

type StorageService struct {
	Storage
}

func (s *StorageService) CreateAccount(ctx context.Context, acc Account) (Account, error) {
	if acc.FriendlyName == "" || !aws.ValidateAWSAccountID(acc.AwsAccountId) {
		return acc, ErrInvalidAccountDetails
	}
	_, err := s.GetAccountByAwsAccountId(ctx, acc.AwsAccountId)
	if err != ErrAccountNotFound {
		return acc, ErrAccountAlreadyExists
	}
	return s.PutAccount(ctx, acc, false)
}
