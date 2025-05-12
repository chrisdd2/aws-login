package auth

import "net/http"

type UserInfo struct {
	Username string
	Email    string
}

type AuthMethod interface {
	RedirectUrl() string
	HandleCallback(r *http.Request) (*UserInfo, error)
}
