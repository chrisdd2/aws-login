package services

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenService interface {
	Create(ctx context.Context, usr *UserInfo, validate bool) (accessToken string, err error)
	Validate(ctx context.Context, token string) (*UserInfo, error)
}

type UserInfo struct {
	Id        string
	Username  string
	Email     string
	Superuser bool
	LoginType string
	IdpToken  string
}

type UserClaims struct {
	jwt.RegisteredClaims
	UserInfo
	Tags map[string]string
}
type tokenServiceImpl struct {
	storage Storage
	key     any
}

func NewToken(storage Storage, key any) TokenService {
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
func (a *tokenServiceImpl) Create(ctx context.Context, usr *UserInfo, validate bool) (string, error) {
	if validate {
		sgUser, err := a.storage.GetUser(ctx, usr.Username)
		if err != nil {
			return "", err
		}
		usr.Superuser = sgUser.Superuser
		usr.Id = sgUser.Name
	}
	accessToken, err := a.signToken(*usr, DefaultTokenExpiration)
	if err != nil {
		return "", err
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
