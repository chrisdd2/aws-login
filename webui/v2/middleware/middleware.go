package middleware

import (
	"context"
	"net/http"

	"github.com/chrisdd2/aws-login/internal/services"
)

type UserCtxKey struct{}

var userCtxKey = UserCtxKey{}

func getUser(r *http.Request) *services.UserInfo {
	usr, ok := r.Context().Value(userCtxKey).(*services.UserInfo)
	if !ok {
		return nil
	}
	return usr
}

func GetUser(r *http.Request) *services.UserInfo {
	return getUser(r)
}

func SetUser(ctx context.Context, user *services.UserInfo) context.Context {
	return context.WithValue(ctx, userCtxKey, user)
}
