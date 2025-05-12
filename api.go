package main

import (
	"net/http"

	"github.com/chrisdd2/aws-login/storage"
)

type ApiRouter struct {
	http.ServeMux
	store storage.Storage
}

func NewApiRouter(store storage.Storage) *ApiRouter {
	r := ApiRouter{}
	r.store = store
	return &r
}
