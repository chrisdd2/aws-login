package auth

import "net/http"

type UserInfo struct {
	Id        string
	Username  string
	Email     string
	Superuser bool
}

type AuthMethod interface {
	RedirectUrl() string
	HandleCallback(r *http.Request) (*UserInfo, error)
}
