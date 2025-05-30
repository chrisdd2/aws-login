package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/internal"
	"github.com/chrisdd2/aws-login/storage"
)

const awsConsoleUrl = "https://console.aws.amazon.com/console/home"
const cookieName = "aws-login-cookie"

type ApiRouter struct {
	http.ServeMux
	store storage.Storage
	auth  auth.AuthMethod
	token auth.LoginToken
	sts   aws.StsClient
}

type userCtx struct{}

var UserCtx userCtx

func NewApiRouter(store storage.Storage, authMethod auth.AuthMethod, token auth.LoginToken, stsCl aws.StsClient) *ApiRouter {
	api := ApiRouter{store: store, auth: authMethod, token: token}
	api.HandleFunc("GET /auth/callback", func(w http.ResponseWriter, r *http.Request) {
		info, err := api.auth.HandleCallback(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		usr, err := store.GetUserByUsername(r.Context(), info.Username)
		if err == storage.ErrUserNotFound {
			usr.Email = info.Email
			usr.Username = info.Username
			usr, err = store.PutUser(r.Context(), usr, false)
			log.Printf("created user [%s]\n", usr.Username)
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
		internal.WriteJson(w, struct {
			Label       string `json:"label"`
			Email       string `json:"email"`
			AccessToken string `json:"access_token"`
		}{
			Label:       info.Username,
			Email:       info.Email,
			AccessToken: jwtToken,
		})
	})
	api.HandleFunc("GET /auth/redirect_url", func(w http.ResponseWriter, r *http.Request) {
		log.Println(api.auth.RedirectUrl())
		internal.WriteJson(w, struct {
			RedirectUrl string `json:"redirect_url"`
		}{RedirectUrl: api.auth.RedirectUrl()})
	})

	userMux := http.ServeMux{}

	userMux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		internal.WriteJson(w, &user)
	})
	userMux.HandleFunc("GET /accounts", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		resp, err := store.ListAccountsForUser(ctx, user.Id, startToken(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		internal.WriteJson(w, &resp)
	})
	userMux.HandleFunc("GET /perm", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		accountId := r.URL.Query().Get("accountId")
		resp, err := store.ListUserPermissions(ctx, user.Id, accountId, "", startToken(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		internal.WriteJson(w, &resp)
	})
	userMux.HandleFunc("POST /perm", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)

		req, err := parseRequest(r, &permRequest{})
		if err != nil {
			http.Error(w, "unable to parse request "+err.Error(), http.StatusInternalServerError)
			return
		}
		user, err := store.GetUserById(ctx, info.Id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if (!user.Superuser) && !checkAccess(ctx, store, user.Id, req.Role, req.AccountId, storage.UserPermissionAdmin, w) {
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
		}, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		internal.WriteJson(w, req)
	})
	userMux.HandleFunc("GET /list", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)
		user, err := store.GetUserByUsername(ctx, info.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if user.Superuser {
			resp, err := store.ListUsers(ctx, "", startToken(r))
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			internal.WriteJson(w, &resp)
			return
		}
		resp, err := store.GetUserById(ctx, user.Id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		internal.WriteJson(w, storage.ListUserResult{Users: []storage.User{resp}})
	})

	accountMux := http.ServeMux{}

	accountMux.HandleFunc("GET /list", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)
		user, err := store.GetUserByUsername(ctx, info.Username)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		if !user.Superuser {
			http.Error(w, "only admins can list accounts", http.StatusUnauthorized)
		}
		resp, err := store.ListAccounts(ctx, startToken(r))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		internal.WriteJson(w, &resp)
	})
	accountMux.HandleFunc("GET /{accountId}/role/{roleId}/credentials", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		account := r.PathValue("accountId")
		role := r.PathValue("roleId")

		if !checkAccess(ctx, store, user.Id, role, account, storage.UserPermissionAssume, w) {
			return
		}

		resp, err := api.sts.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &role, RoleSessionName: &user.Username, DurationSeconds: &aws.SessionDuration})
		if err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		response := struct {
			AccessKeyId     string `json:"access_key_id,omitempty"`
			SecretAccessKey string `json:"secret_access_key,omitempty"`
			SessionToken    string `json:"session_token,omitempty"`
		}{*resp.Credentials.AccessKeyId, *resp.Credentials.SecretAccessKey, *resp.Credentials.SessionToken}
		internal.WriteJson(w, response)
	})
	accountMux.HandleFunc("GET /{accountId}/role/{roleId}/login", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := ctx.Value(UserCtx).(*auth.UserInfo)
		account := r.PathValue("accountId")
		role := r.PathValue("roleId")

		if !checkAccess(ctx, store, user.Id, role, account, storage.UserPermissionAssume, w) {
			return
		}

		url, err := aws.GenerateSigninUrl(ctx, api.sts, role, user.Username, awsConsoleUrl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		internal.WriteJson(w, struct {
			SigninUrl string `json:"signin_url"`
		}{url})
	})
	accountMux.HandleFunc("GET /bootstrap_template", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)
		user, err := store.GetUserById(ctx, info.Id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !user.Superuser {
			http.Error(w, "only superuser can access this endpoint", http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/yaml")
		err = aws.BootstrapTemplate(ctx, stsCl, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	accountMux.HandleFunc("GET /{accountId}/ops", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		account := r.PathValue("accountId")
		acc, err := store.GetAccountById(ctx, account)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// need to assume the management role
		cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(stscreds.NewAssumeRoleProvider(stsCl, acc.ArnForRole(aws.OpsRole))))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cfnCl := cloudformation.NewFromConfig(cfg)
		stackName := aws.StackName
		resp, err := cfnCl.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackName})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		internal.WriteJson(w, struct {
			Status string `json:"status"`
		}{Status: string(resp.Stacks[0].StackStatus)})
	})

	accountMux.HandleFunc("POST /{accountId}/ops", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info := ctx.Value(UserCtx).(*auth.UserInfo)
		account := r.PathValue("accountId")
		user, err := store.GetUserById(ctx, info.Id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !user.Superuser {
			http.Error(w, "only superuser can access this endpoint", http.StatusInternalServerError)
			return
		}
		acc, err := store.GetAccountById(ctx, account)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(stscreds.NewAssumeRoleProvider(stsCl, acc.ArnForRole(aws.OpsRole))))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		cfnCl := cloudformation.NewFromConfig(cfg)
		err = aws.DeployBaseStack(ctx, cfnCl, acc.ArnForRole(aws.OpsRole))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		internal.WriteJson(w, struct {
			StackName string `json:"stackName"`
		}{StackName: aws.StackName})
	})

	api.Handle("/user/", http.StripPrefix("/user", protectedEndpoint(token, &userMux)))
	api.Handle("/account/", http.StripPrefix("/account", protectedEndpoint(token, &accountMux)))
	return &api
}

func protectedEndpoint(token auth.LoginToken, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	})
}

func startToken(r *http.Request) *string {
	tok := r.URL.Query().Get("startToken")
	if tok == "" {
		return nil
	}
	return &tok
}

func checkAccess(ctx context.Context, store storage.Storage, userId, role, account, scope string, w http.ResponseWriter) bool {
	ok := false
	result, err := store.ListUserPermissions(ctx, userId, account, storage.UserPermissionAssume, nil)
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
		http.Error(w, fmt.Sprintf("no access for [%s]", scope), http.StatusForbidden)
		return false
	}
	return true
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
