package api

import (
	"github.com/chrisdd2/aws-login/services"
	"github.com/go-chi/chi/v5"
)

func V1Api(accountsSrv services.AccountService, auth services.AuthService) chi.Router {
	r := chi.NewRouter()
	return r
}
