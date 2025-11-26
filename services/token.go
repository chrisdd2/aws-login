package services

import (
	"context"

	"github.com/chrisdd2/aws-login/auth"
	sg "github.com/chrisdd2/aws-login/storage"
)

type TokenService interface {
	Create(ctx context.Context, usr *auth.UserInfo) (accessToken string, err error)
	Validate(ctx context.Context, token string) (*auth.UserInfo, error)
}

type tokenServiceImpl struct {
	storage sg.Service
	token   auth.LoginToken
}

func (a *tokenServiceImpl) CreateAccessToken(ctx context.Context, usr *auth.UserInfo) (string, error) {
	sgUser, err := a.storage.GetUserByName(ctx, usr.Username)
	if err == sg.ErrUserNotFound {
		// create it
		sgUser, err = a.storage.PutUser(ctx, &sg.User{
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

func (a *tokenServiceImpl) ValidateAccessToken(token string) (*auth.UserInfo, error) {
	claims, err := a.token.Validate(token)
	if err != nil {
		return nil, err
	}
	return &claims.UserInfo, nil
}
