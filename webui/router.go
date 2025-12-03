package webui

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
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
	case "wrong_credentials":
		return "Invalid username/password"
	default:
		return "Interval server error"
	}
}

func Router(tokenSvc services.TokenService, authSvcs []services.AuthService, rolesSvc services.RolesService, accountSrvc services.AccountService, adminUsername, adminPassword string) chi.Router {
	r := chi.NewRouter()

	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		loginType := r.URL.Query().Get("type")
		for _, idp := range authSvcs {
			if idp.Name() != loginType {
				continue
			}
			http.Redirect(w, r, idp.RedirectUrl(), http.StatusTemporaryRedirect)
			return
		}
		errorParam := r.URL.Query().Get("error")
		data := templates.LoginData{ErrorString: loginErrorString(errorParam)}
		for _, idp := range authSvcs {
			name := idp.Name()
			prettyName := strings.ToUpper(name[0:1]) + name[1:]
			data.LoginType = append(data.LoginType, struct {
				Name string
				Desc string
			}{Name: idp.Name(), Desc: fmt.Sprintf("Sign in with %s", prettyName)})
		}
		if err := templates.LoginTemplate(w, data); err != nil {
			render.Status(r, http.StatusInternalServerError)
		}
	})
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		loginType := r.URL.Query().Get("type")
		if loginType == "userpass" {
			r.ParseForm()
			username := r.Form.Get("username")
			password := r.Form.Get("password")
			if !(username == adminUsername && password == adminPassword) {
				log.Println(username, password)
				http.Redirect(w, r, "/login?error=wrong_credentials", http.StatusSeeOther)
				return
			}
			accessToken, _ := tokenSvc.Create(r.Context(), &services.UserInfo{Username: username, Email: "admin@admin", Superuser: true, LoginType: "userpass"}, false)
			sendAccessToken(w, r, accessToken)
			return
		}
		if err := templates.LoginTemplate(w, templates.LoginData{ErrorString: loginErrorString("")}); err != nil {
			render.Status(r, http.StatusInternalServerError)
		}
	})

	for _, idp := range authSvcs {
		// idp response
		r.HandleFunc(idp.CallbackEndpoint(), func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			info, err := idp.CallbackHandler(r)
			if err != nil {
				render.Status(r, http.StatusUnauthorized)
				log.Println(err)
				render.JSON(w, r, err)
			}
			accessToken, err := tokenSvc.Create(ctx, &services.UserInfo{Username: info.Username, Email: info.Email, LoginType: idp.Name()}, true)
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
			sendAccessToken(w, r, accessToken)
		})

	}
	g := r.With(guardMiddleware(tokenSvc))
	mainHandler := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)
		var roles []*appconfig.RoleAttachment
		var err error
		if user.Superuser {
			roles, err = rolesSvc.RolesForAccount(ctx, "")
		} else {
			roles, err = rolesSvc.UserPermissions(ctx, user.Username, "", "")
		}
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
			log.Println(err)
			render.Status(r, http.StatusInternalServerError)
		}
	}
	g.Get("/", mainHandler)
	g.Post("/", mainHandler)
	g.Get("/account/console", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)

		query := r.URL.Query()
		account := query.Get("account")
		role := query.Get("role")
		if account == "" || role == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if !user.Superuser {
			perms, err := rolesSvc.UserPermissions(ctx, user.Username, role, account)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				log.Println(err)
				return
			}
			if len(perms) == 0 || !slices.Contains(perms[0].Permissions, "console") {
				w.WriteHeader(http.StatusUnauthorized)
				render.JSON(w, r, struct{ Error string }{Error: "no permission to use this role"})
			}
		}
		url, err := rolesSvc.Console(ctx, account, role, user.Username)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			log.Println(err)
			return
		}
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
	g.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		user := getUser(r)

		cookie, _ := r.Cookie("aws-login-cookie")
		if cookie != nil {
			cookie.MaxAge = -1
			http.SetCookie(w, cookie)
		}
		// add redirect after
		vals := url.Values{}
		vals.Add("redirect_url","http://localhost:3000")
		for _, idp := range authSvcs {
			if user.LoginType == idp.Name() {
				http.Redirect(w, r, idp.LogoutUrl() + "?"+vals.Encode(), http.StatusTemporaryRedirect)
				return
			}
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

func sendAccessToken(w http.ResponseWriter, r *http.Request, accessToken string) {
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
}
