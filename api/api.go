package api

import (
	"context"
	"errors"

	sg "github.com/chrisdd2/aws-login/storage"
)

type Api struct {
	be sg.StorageBackend
}

func ValidateAWSAccountID(accountID int) bool {
	return accountID > 100000000000 && accountID <= 999999999999
}

var ErrInvalidAccountDetails error = errors.New("invalid account details")
var ErrAccountAlreadyExists error = errors.New("account already exists")

func (a *Api) CreateAccount(ctx context.Context, acc *sg.Account) (*sg.Account, error) {
	if acc.Name == "" || ValidateAWSAccountID(acc.AwsAccountId) {
		return nil, ErrInvalidAccountDetails
	}
	_, err := a.be.GetAccountByAwsAccountId(ctx, acc.AwsAccountId)
	if err != sg.ErrAccountNotFound {
		return nil, ErrAccountAlreadyExists
	}
	acc, err = a.be.PutAccount(ctx, acc, false)
	if err != nil {
		return nil, err
	}
	_, err = a.be.PutRole(ctx, sg.DeveloperRoleDefinition(acc.Id, sg.DeveloperRole), false)
	if err != nil {
		return nil, err
	}
	_, err = a.be.PutRole(ctx, sg.ReadOnlyRoleDefinition(acc.Id, sg.ReadOnlyRole), false)
	if err != nil {
		return nil, err
	}
	return acc, nil
}
