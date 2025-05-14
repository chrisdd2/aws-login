package main

import (
	"context"
	"encoding/json"
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

func NewApiRouter(store storage.Storage, authMethod auth.AuthMethod, token auth.LoginToken) *ApiRouter {
	api := ApiRouter{store: store, auth: authMethod, token: token}
	api.HandleFunc("/auth/callback", func(w http.ResponseWriter, r *http.Request) {
		info, err := api.auth.HandleCallback(r)
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
		writeJson(w, struct {
			Label       string `json:"label"`
			Email       string `json:"email"`
			AccessToken string `json:"access_token"`
		}{
			Label:       info.Username,
			Email:       info.Email,
			AccessToken: jwtToken,
		})
	})
	api.HandleFunc("/auth/redirect_url", func(w http.ResponseWriter, r *http.Request) {
		writeJson(w, struct {
			RedirectUrl string `json:"redirect_url"`
		}{RedirectUrl: api.auth.RedirectUrl()})
	})

	startToken := func(r *http.Request) *string {
		tok := r.URL.Query().Get("startToken")
		if tok == "" {
			return nil
		}
		return &tok
	}

	api.get("/user", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		writeJson(w, &user)
	})
	api.get("/user/accounts", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		resp, err := store.ListAccountsForUser(ctx, user.Id, startToken(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		writeJson(w, &resp)
	})
	api.get("/user/perms", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		accountId := r.URL.Query().Get("accountId")
		resp, err := store.ListUserPermissions(ctx, user.Id, accountId, "", startToken(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		writeJson(w, &resp)
	})

	api.get("/user/list", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)
		user, err := store.GetUserByEmail(ctx, info.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if user.Superuser {
			http.Error(w, "only admins can list users", http.StatusUnauthorized)
		}
		resp, err := store.ListUsers(ctx, "", startToken(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		writeJson(w, &resp)
	})
	api.get("/accounts", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)
		user, err := store.GetUserByEmail(ctx, info.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if user.Superuser {
			http.Error(w, "only admins can list accounts", http.StatusUnauthorized)
		}
	})

	checkAccess := func(ctx context.Context, userId, role, account, scope string, w http.ResponseWriter) bool {
		ok := false
		result, err := api.store.ListUserPermissions(ctx, userId, account, storage.UserPermissionAssume, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return false
		}
		for _, perm := range result.UserPermissions {
			if slices.Contains(perm.Value, role) {
				ok = true
				break
			}
		}
		if !ok {
			http.Error(w, "no access to assume", http.StatusForbidden)
			return false
		}
		return true
	}

	api.post("/perm", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)

		req, err := parseRequest(r, &permRequest{})
		if err != nil {
			http.Error(w, "unable to parse request "+err.Error(), http.StatusInternalServerError)
			return
		}
		user, err := store.GetUserByEmail(ctx, info.Email)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if (!user.Superuser) && !checkAccess(ctx, user.Id, req.Role, req.AccountId, storage.UserPermissionAdmin, w) {
			return
		}
		if !user.Superuser && req.Scope == storage.UserPermissionAdmin {
			http.Error(w, "only superuser can grant admin", http.StatusInternalServerError)
			return
		}

		err = store.PutUserPermission(ctx, storage.UserPermission{
			UserPermissionId: storage.UserPermissionId{
				UserId:    user.Id,
				AccountId: req.AccountId,
				Scope:     req.Scope,
			},
			Value: []string{req.Role},
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJson(w, req)
	})

	api.get("/aws/credentials", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		account := r.URL.Query().Get("account")
		role := r.URL.Query().Get("role")

		if !checkAccess(ctx, user.Id, role, account, storage.UserPermissionAssume, w) {
			return
		}

		resp, err := api.sts.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &role, RoleSessionName: &user.Username, DurationSeconds: &sessionDuration})
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
	})
	api.get("/aws/login", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		account := r.URL.Query().Get("account")
		role := r.URL.Query().Get("role")

		if !checkAccess(ctx, user.Id, role, account, storage.UserPermissionAssume, w) {
			return
		}

		url, err := generateSigninUrl(ctx, api.sts, role, user.Username, awsConsoleUrl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Location", url)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
	return &api
}

func (router *ApiRouter) handle(method, pattern string, h http.HandlerFunc) {
	router.HandleFunc(pattern, protectedEndpoint(router.token, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}))
}
func (router *ApiRouter) get(pattern string, h http.HandlerFunc) {
	router.handle("GET", pattern, h)
}
func (router *ApiRouter) post(pattern string, h http.HandlerFunc) {
	router.handle("POST", pattern, h)
}

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
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserCtx, &user)))
	}
}

func writeJson(w http.ResponseWriter, v any) {
	w.Header().Add("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		log.Println(err)
	}
}

func parseRequest[V any](r *http.Request, v V) (V, error) {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return v, dec.Decode(v)
}

type permRequest struct {
	AccountId string `json:"account_id,omitempty"`
	Role      string `json:"role,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

func (p *permRequest) Validate() bool {
	return p.AccountId != "" && p.Role != "" && (p.Scope == storage.UserPermissionAdmin || p.Scope == storage.UserPermissionAssume)
}
