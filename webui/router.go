package webui

import (
	"context"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/chrisdd2/aws-login/services"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const authCookie = "aws-login-cookie"

func loginErrorString(v string) string {
	if v == "" {
		return ""
	}
	switch v {
	case "invalid_cookie":
		return "Authentication cookie is invalid, log out and retry"
	case "user_not_found":
		return "User not found in database.\nContact an administrator"
	default:
		return "Interval server error"
	}
}

func Router(tokenSvc services.TokenService, authSvc services.AuthService, rolesSvc services.RolesService, accountSrvc services.AccountService) chi.Router {
	r := chi.NewRouter()
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		loginType := r.URL.Query().Get("type")
		switch loginType {
		case "keycloak":
			http.Redirect(w, r, authSvc.RedirectUrl(), http.StatusTemporaryRedirect)
		default:
			errorParam := r.URL.Query().Get("error")
			if err := templates.LoginTemplate(w, templates.LoginData{ErrorString: loginErrorString(errorParam)}); err != nil {
				render.Status(r, http.StatusInternalServerError)
			}
		}
	})
	// idp response
	r.HandleFunc(authSvc.CallbackEndpoint(), func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info, err := authSvc.CallbackHandler(r)
		if err != nil {
			render.Status(r, http.StatusUnauthorized)
			log.Println(err)
			render.JSON(w, r, err)
		}
		accessToken, err := tokenSvc.Create(ctx, &services.UserInfo{Username: info.Username, Email: info.Email})
		if err == services.ErrUserNotFound {
			http.Redirect(w, r, "/login?error=user_not_found", http.StatusTemporaryRedirect)
			return
		}
		if err != nil {
			render.Status(r, http.StatusUnauthorized)
			log.Println(err)
			render.JSON(w, r, err)
			return
		}
		cookie := http.Cookie{
			Name:     authCookie,
			Value:    accessToken,
			Path:     "/",
			MaxAge:   int((time.Hour * 8) / time.Second),
			Expires:  time.Now().UTC().Add(time.Hour * 8),
			HttpOnly: true,
		}
		http.SetCookie(w, &cookie)
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
	g := r.With(guardMiddleware(tokenSvc))
	g.Get("/", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)
		roles, err := rolesSvc.UserPermissions(ctx, user.Id, "")
		if err != nil {
			render.Status(r, http.StatusInternalServerError)
			log.Println(err)
			render.JSON(w, r, err)
		}
		templateRoles := make([]templates.Role, 0, len(roles))
		for _, role := range roles {
			acc, err := accountSrvc.GetFromAccountName(ctx, role.AccountName)
			if err != nil {
				render.Status(r, http.StatusInternalServerError)
				log.Println(err)
				render.JSON(w, r, err)
				return
			}
			templateRoles = append(templateRoles, templates.Role{
				AccountName:    role.AccountName,
				AccountId:      acc.AwsAccountId,
				RoleName:       role.RoleName,
				HasCredentials: slices.Contains(role.Permissions, "credentials"),
				HasConsole:     slices.Contains(role.Permissions, "console"),
			})
		}
		data := templates.RolesData{
			Navbar: templates.Navbar{Username: user.Username},
			Roles:  templateRoles,
		}
		if err := templates.RolesTemplate(w, data); err != nil {
			render.Status(r, http.StatusInternalServerError)
		}
	})
	return r
}

type userCtxKey struct{}

var UserCtxKey = userCtxKey{}

func getUser(r *http.Request) *services.UserInfo {
	return r.Context().Value(UserCtxKey).(*services.UserInfo)
}
func guardMiddleware(tokenService services.TokenService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("aws-login-cookie")
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			info, err := tokenService.Validate(r.Context(), cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/login?error=invalid_cookie", http.StatusSeeOther)
				log.Println(err)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), UserCtxKey, info))
			next.ServeHTTP(w, r)
		})
	}
}
