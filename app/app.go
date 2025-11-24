package api

import (
	"context"
	"errors"
	"time"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	sg "github.com/chrisdd2/aws-login/storage"
)

type App struct {
	Storage sg.Service
	token   auth.LoginToken
	aws     aws.AwsApiCaller
}

func ValidateAWSAccountID(accountID int) bool {
	return accountID > 100000000000 && accountID <= 999999999999
}

var ErrInvalidAccountDetails error = errors.New("invalid account details")
var ErrAccountAlreadyExists error = errors.New("account already exists")

func (a *App) getUser(ctx context.Context, id string) (*sg.User, error) {
	users, err := a.Storage.GetUsers(ctx, id)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, errors.New("user not found")
	}
	return users[0], nil
}

func (a *App) CreateAccount(ctx context.Context, userId string, acc *sg.Account) (*sg.Account, error) {

	// Permission check
	user, err := a.getUser(ctx, userId)
	if err != nil {
		return nil, err
	}
	if !user.Superuser {
		return nil, errors.New("only superusers can create accounts")
	}

	// Account validation
	if acc.Name == "" || ValidateAWSAccountID(acc.AwsAccountId) {
		return nil, ErrInvalidAccountDetails
	}
	_, err = a.Storage.GetAccountByAwsAccountId(ctx, acc.AwsAccountId)
	if err != sg.ErrAccountNotFound {
		return nil, ErrAccountAlreadyExists
	}

	// Commit account
	acc.UpdateBy = userId
	acc.UpdateTime = time.Now().UTC()
	acc, err = a.Storage.PutAccount(ctx, acc, false)
	if err != nil {
		return nil, err
	}

	// Add the default roles
	_, err = a.Storage.PutRole(ctx, sg.DeveloperRoleDefinition(acc.Id, sg.DeveloperRole), false)
	if err != nil {
		return nil, err
	}
	_, err = a.Storage.PutRole(ctx, sg.ReadOnlyRoleDefinition(acc.Id, sg.ReadOnlyRole), false)
	if err != nil {
		return nil, err
	}
	return acc, nil
}

func (a *App) CreateAccessToken(ctx context.Context, usr *auth.UserInfo) (string, error) {
	sgUser, err := a.Storage.GetUserByName(ctx, usr.Username)
	if err == sg.ErrUserNotFound {
		// create it
		sgUser, err = a.Storage.PutUser(ctx, &sg.User{
			Name:      usr.Username,
			Email:     usr.Email,
			Superuser: false,
		}, false)
	}
	if err != nil {
		return "", err
	}
	usr.Superuser = sgUser.Superuser
	usr.Id = sgUser.Id
	accessToken, err := a.token.SignToken(*usr, auth.DefaultTokenExpiration)
	if err != nil {
		return "", nil
	}
	return accessToken, nil
}

func (a *App) ValidateAccessToken(token string) (*auth.UserInfo, error) {
	claims, err := a.token.Validate(token)
	if err != nil {
		return nil, err
	}
	return &claims.UserInfo, nil
}
