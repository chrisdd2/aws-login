package services

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chrisdd2/aws-login/store"
	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidClaims = errors.New("unable to parse claims")

const DefaultTokenExpiration = time.Hour * 24

type TokenService interface {
	Create(ctx context.Context, usr *UserInfo, validate bool) (accessToken string, err error)
	Validate(ctx context.Context, token string) (*UserInfo, error)
}

type UserInfo struct {
	Username     string
	FriendlyName string
	Superuser    bool
	LoginType    string
	IdpToken     string
}

func (u UserInfo) DebugPrint() {
	fmt.Println("{")
	fmt.Println("\tUsername:", u.Username)
	fmt.Println("\tFriendlyName:", u.FriendlyName)
	fmt.Println("\tSuperuser:", u.Superuser)
	fmt.Println("\tLoginType:", u.LoginType)
	fmt.Println("\tIdpToken:", u.IdpToken)
	fmt.Println("}")
}

type UserClaims struct {
	jwt.RegisteredClaims
	UserInfo
	Tags map[string]string
}
type tokenServiceImpl struct {
	storage store.Store
	key     any
}

func NewToken(storage store.Store, key any) TokenService {
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
		_, err := store.GetResource(ctx, a.storage, store.ResourceTypeUser, usr.Username)
		if err != nil {
			return "", fmt.Errorf("storage.GetUser: %w", err)
		}
		_, err = store.GetUserPermission(ctx, a.storage, store.UserPermissionSuperUser, usr.Username, "", "")
		usr.Superuser = err == nil
	}
	accessToken, err := a.signToken(*usr, DefaultTokenExpiration)
	if err != nil {
		return "", fmt.Errorf("jwt.SignedString: %w", err)
	}
	return accessToken, nil
}

func (a *tokenServiceImpl) Validate(ctx context.Context, tokenStr string) (*UserInfo, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (any, error) {
		return a.key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseWithClaims: %w", err)
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}
	return &claims.UserInfo, nil
}
