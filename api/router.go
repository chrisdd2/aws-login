package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/chrisdd2/aws-login/internal/services"
	"github.com/chrisdd2/aws-login/internal/services/account"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

var (
	ErrUnknownAuthType            = errors.New("unknown auth type")
	ErrMissingAuthorizationHeader = errors.New("missing Authorization header")
)

type ApiError struct {
	Message string `json:"message"`
}

func sendError(w http.ResponseWriter, r *http.Request, err error, statusCode int) {
	render.Status(r, statusCode)
	render.JSON(w, r, ApiError{Message: err.Error()})
}
func V1Api(accountsSvc account.AccountService, idps []services.AuthService, roleSvc services.RolesService, tokenSvc services.TokenService) chi.Router {
	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		render.JSON(w, r, struct {
			Message string
		}{Message: "ok"})
	})
	r.Post("/auth", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		authType := query.Get("type")
		requestForm := struct {
			AccessToken string `json:"access_token"`
		}{}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&requestForm); err != nil {
			sendError(w, r, err, http.StatusBadRequest)
			return
		}
		for _, idp := range idps {
			if idp.Details().Name == authType {
				info, err := idp.TokenLogin(r, requestForm.AccessToken)
				if err != nil {
					sendError(w, r, fmt.Errorf("idp.TokenLogin: %w", err), http.StatusBadRequest)
					return
				}
				accessToken, err := tokenSvc.Create(r.Context(), &services.UserInfo{
					Username:     info.Username,
					FriendlyName: info.FriendlyName,
					LoginType:    authType,
					IdpToken:     requestForm.AccessToken,
				}, false)
				if err != nil {
					sendError(w, r, fmt.Errorf("token.Create: %w", err), http.StatusInternalServerError)
					return
				}
				render.JSON(w, r, struct {
					Authorization string
				}{Authorization: fmt.Sprintf("Bearer %s", accessToken)})
				return
			}
		}
		sendError(w, r, ErrUnknownAuthType, http.StatusBadRequest)
	})
	r.With(guardMiddleware(tokenSvc)).Route("/account", func(r chi.Router) {
		r.Get("/console", func(w http.ResponseWriter, r *http.Request) {
			usr := getUser(r)
			query := r.URL.Query()
			account := query.Get("account")
			role := query.Get("role")
			if account == "" || role == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ctx := r.Context()
			url, err := roleSvc.Console(ctx, account, role, usr.Username)
			if err != nil {
				if errors.Is(err, services.ErrRoleUnauthorized) {
					sendError(w, r, err, http.StatusUnauthorized)
					return
				}
				sendError(w, r, err, http.StatusUnauthorized)
				return
			}
			render.JSON(w, r, struct {
				RedirectUrl string
			}{RedirectUrl: url})
		})
		r.Get("/credentials", func(w http.ResponseWriter, r *http.Request) {
			usr := getUser(r)
			query := r.URL.Query()
			account := query.Get("account")
			role := query.Get("role")
			fmt := query.Get("format")
			if account == "" || role == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			ctx := r.Context()
			creds, err := roleSvc.Credentials(ctx, account, role, usr.Username)
			if err != nil {
				if errors.Is(err, services.ErrRoleUnauthorized) {
					sendError(w, r, err, http.StatusUnauthorized)
					return
				}
				sendError(w, r, err, http.StatusUnauthorized)
				return
			}
			if fmt != "" {
				render.PlainText(w, r, creds.Format(fmt))
				return
			}
			render.JSON(w, r, creds)
		})
	})

	return r
}

type userCtxKey struct{}

var UserCtxKey = userCtxKey{}

func getUser(r *http.Request) *services.UserInfo {
	usr, ok := r.Context().Value(UserCtxKey).(*services.UserInfo)
	if !ok {
		return &services.UserInfo{}
	}
	return usr
}
func guardMiddleware(tokenService services.TokenService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok {
				sendError(w, r, ErrMissingAuthorizationHeader, http.StatusBadRequest)
				return
			}
			info, err := tokenService.Validate(r.Context(), token)
			if err != nil {
				sendError(w, r, fmt.Errorf("token.Validate: %w", err), http.StatusUnauthorized)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), UserCtxKey, info))
			next.ServeHTTP(w, r)
		})
	}
}
