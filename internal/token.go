package internal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type UserClaims struct {
	jwt.RegisteredClaims
	Username   string
	Principals []string
	IdpToken   string
}

func SignToken(key []byte, username string, principals []string, idpToken string, expiration time.Duration) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodHS256,
		UserClaims{
			Username:   username,
			Principals: principals,
			IdpToken:   idpToken,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().UTC().Add(expiration)),
			},
		},
	)
	return token.SignedString(key)
}

func ParseToken(ctx context.Context, key []byte, tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr,
		&UserClaims{},
		func(token *jwt.Token) (any, error) {
			return key, nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt.ParseWithClaims: %w", err)
	}
	claims, ok := token.Claims.(*UserClaims)
	if !ok {
		return nil, errors.New("unable to parse claims")
	}
	return claims, err
}
