package auth

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const DefaultTokenExpiration = time.Hour * 24 * 30

type LoginToken struct {
	Key any
}

type UserClaims struct {
	jwt.RegisteredClaims
	UserInfo
	Tags map[string]string
}

func (t *LoginToken) SignToken(usr UserInfo, expiration time.Duration) (string, error) {
	claims := UserClaims{
		UserInfo: usr,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiration)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(t.Key)
}

func (t *LoginToken) Validate(tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return t.Key, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, errors.New("unable to parse claims")
	}
	return claims, nil
}
