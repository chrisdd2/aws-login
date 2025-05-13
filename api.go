package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/storage"
)

const awsConsoleUrl = "https://console.aws.amazon.com/console/home"

type ApiRouter struct {
	http.ServeMux
	store storage.Storage
	auth  auth.AuthMethod
	token auth.LoginToken
	sts   StsClient
}

type userCtx struct{}

var UserCtx userCtx

func protectedEndpoint(token auth.LoginToken, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if authHeader == "" {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		user, err := token.Validate(authHeader)
		if err != nil {
			http.Error(w, "unable to validate authorization token", http.StatusUnauthorized)
			log.Println(err)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), UserCtx, &user))
		h.ServeHTTP(w, r)
	}
}

func NewApiRouter(store storage.Storage, authMethod auth.AuthMethod, token auth.LoginToken) *ApiRouter {
	router := ApiRouter{store: store, auth: authMethod, token: token}
	router.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		info, err := router.auth.HandleCallback(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		usr, err := store.GetUserByEmail(r.Context(), info.Email)
		if err == storage.ErrUserNotFound {
			usr.Email = info.Email
			usr.Label = info.Username
			usr, err = store.PutUser(r.Context(), usr)
			log.Println(usr)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		info.Id = usr.Id
		jwtToken, err := token.SignToken(*info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprintf(w, "{ \"token\": \"%s\"}", jwtToken)
	})
	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, router.auth.RedirectUrl(), http.StatusTemporaryRedirect)
	})

	router.HandleFunc("/credentials", protectedEndpoint(router.token, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		account := r.URL.Query().Get("account")
		role := r.URL.Query().Get("role")

		ok := false
		for perm, err := range router.store.ListUserPermissions(ctx, user.Id, account, storage.UserPermissionAssume) {
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if slices.Contains(perm.Value, role) {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "no access to assume", http.StatusForbidden)
			return
		}
		resp, err := router.sts.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &role, RoleSessionName: &user.Username, DurationSeconds: &sessionDuration})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		response := struct {
			AccessKeyId     string `json:"access_key_id,omitempty"`
			SecretAccessKey string `json:"secret_access_key,omitempty"`
			SessionToken    string `json:"session_token,omitempty"`
		}{*resp.Credentials.AccessKeyId, *resp.Credentials.SecretAccessKey, *resp.Credentials.SessionToken}
		writeJson(w, response)
	}))
	router.HandleFunc("/consolelogin", protectedEndpoint(router.token, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		account := r.URL.Query().Get("account")
		role := r.URL.Query().Get("role")

		ok := false
		for perm, err := range router.store.ListUserPermissions(ctx, user.Id, account, storage.UserPermissionAssume) {
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if slices.Contains(perm.Value, role) {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "no access to assume", http.StatusForbidden)
			return
		}
		url, err := generateSigninUrl(ctx, router.sts, role, user.Username, awsConsoleUrl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Location", url)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}))
	return &router
}

func writeJson(w http.ResponseWriter, v any) {
	w.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		log.Println(err)
	}
}
