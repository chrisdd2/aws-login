package services

import (
	"context"
	"errors"
	"time"

	"github.com/chrisdd2/aws-login/storage"
	sg "github.com/chrisdd2/aws-login/storage"
	"github.com/golang-jwt/jwt/v5"
)

type TokenService interface {
	Create(ctx context.Context, usr *UserInfo) (accessToken string, err error)
	Validate(ctx context.Context, token string) (*UserInfo, error)
}

type UserInfo struct {
	Id        string
	Username  string
	Email     string
	Superuser bool
}

type UserClaims struct {
	jwt.RegisteredClaims
	UserInfo
	Tags map[string]string
}
type tokenServiceImpl struct {
	storage sg.Service
	key     any
}

func NewToken(storage storage.Service, key any) TokenService {
	return &tokenServiceImpl{storage, key}
}

func (t *tokenServiceImpl) signToken(usr UserInfo, expiration time.Duration) (string, error) {
	claims := UserClaims{
		UserInfo: usr,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.key)
}
func (a *tokenServiceImpl) Create(ctx context.Context, usr *UserInfo) (string, error) {
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
	accessToken, err := a.signToken(*usr, DefaultTokenExpiration)
	if err != nil {
		return "", nil
	}
	return accessToken, nil
}

func (a *tokenServiceImpl) Validate(ctx context.Context, tokenStr string) (*UserInfo, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return a.key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, errors.New("unable to parse claims")
	}
	return &claims.UserInfo, nil
}

const DefaultTokenExpiration = time.Hour * 24
