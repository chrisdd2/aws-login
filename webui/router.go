package webui

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
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

func Router(tokenSvc services.TokenService, authSvcs []services.AuthService, rolesSvc services.RolesService, accountSrvc services.AccountService, adminUsername, adminPassword string, rootUrl string) chi.Router {
	r := chi.NewRouter()
	r.Get("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, templates.Static, "faveicon.ico")
	})
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
			sendError(w, r, err)
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
			sendError(w, r, err)
		}
	})

	for _, idp := range authSvcs {
		// idp response
		r.HandleFunc(idp.CallbackEndpoint(), func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			info, err := idp.CallbackHandler(r)
			if err != nil {
				sendUnathorized(w, r, err)
				return
			}
			accessToken, err := tokenSvc.Create(ctx, &services.UserInfo{Username: info.Username, Email: info.Email, LoginType: idp.Name(), IdpToken: info.IdpToken}, true)
			if err == services.ErrUserNotFound {
				http.Redirect(w, r, "/login?error=user_not_found", http.StatusTemporaryRedirect)
				return
			}
			if err != nil {
				sendUnathorized(w, r, err)
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
			sendError(w, r, err)
			return
		}
		templateRoles := make([]templates.Role, 0, len(roles))
		for _, role := range roles {
			acc, err := accountSrvc.GetFromAccountName(ctx, role.AccountName)
			if err != nil {
				sendError(w, r, err)
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
			Navbar: templates.Navbar{Username: user.Username, HasAdmin: user.Superuser},
			Roles:  templateRoles,
		}
		if err := templates.RolesTemplate(w, data); err != nil {
			sendError(w, r, err)
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
		// auth check
		perms, err := rolesSvc.UserPermissions(ctx, user.Username, role, account)
		if err != nil {
			sendError(w, r, err)
			return
		}
		if len(perms) == 0 || !slices.Contains(perms[0].Permissions, appconfig.RolePermissionConsole) {
			sendUnathorized(w, r, errors.New("no permission to use this role"))
			return
		}

		// do login
		url, err := rolesSvc.Console(ctx, account, role, user.Username)
		if err != nil {
			sendError(w, r, err)
			return
		}
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	})
	g.Get("/account/credentials", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)

		query := r.URL.Query()
		account := query.Get("account")
		format := query.Get("format")
		role := query.Get("role")
		if account == "" || role == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// auth check
		perms, err := rolesSvc.UserPermissions(ctx, user.Username, role, account)
		if err != nil {
			sendError(w, r, err)
			return
		}
		if len(perms) == 0 || !slices.Contains(perms[0].Permissions, appconfig.RolePermissionCredentials) {
			sendUnathorized(w, r, errors.New("no permission to use this role"))
			return
		}

		// do login
		creds, err := rolesSvc.Credentials(ctx, account, role, user.Username)
		if err != nil {
			sendError(w, r, err)
			return
		}

		if format == "" {
			format = "linux"
		}
		render.PlainText(w, r, creds.Format(format))
	})
	g.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		user := getUser(r)

		cookie, _ := r.Cookie(authCookie)
		if cookie != nil {
			cookie.MaxAge = -1
			http.SetCookie(w, cookie)
		}
		if rootUrl == "" {
			rootUrl = "/"
		}
		for _, idp := range authSvcs {
			if user.LoginType == idp.Name() {
				http.Redirect(w, r, idp.LogoutUrl(rootUrl, user.IdpToken), http.StatusTemporaryRedirect)
				return
			}
		}
		// its userpass, redirect to main
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})
	g.With(superOnlyMiddleware()).Get("/account/deploy", func(w http.ResponseWriter, r *http.Request) {
		user := getUser(r)
		ctx := r.Context()
		account := r.URL.Query().Get("account")
		if account == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if err := accountSrvc.Deploy(ctx, user.Username, account); err != nil {
			sendError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/account/watch?account=%s", account), http.StatusTemporaryRedirect)
	})
	g.With(superOnlyMiddleware()).Get("/account/watch", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)
		query := r.URL.Query()
		account := query.Get("account")
		if account == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stackId := query.Get("stackId")
		events, err := accountSrvc.StackUpdates(ctx, account, stackId)
		if err != nil {
			sendError(w, r, err)
			return
		}
		if err := templates.WatchTemplate(w, templates.WatchData{
			Navbar: templates.Navbar{Username: user.Username, HasAdmin: user.Superuser},
			Events: events,
		}); err != nil {
			sendError(w, r, err)
		}

	})
	g.With(superOnlyMiddleware()).Get("/account/destroy", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		query := r.URL.Query()
		account := query.Get("account")
		if account == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		stackId, err := accountSrvc.DestroyStack(ctx, account)
		if err != nil {
			sendError(w, r, err)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("/account/watch?account=%s?stackId=%s", account, stackId), http.StatusTemporaryRedirect)

	})
	g.With(superOnlyMiddleware()).Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)

		accounts, err := accountSrvc.ListAccounts(ctx)
		if err != nil {
			sendError(w, r, err)
			return
		}
		templateAccounts := make([]templates.Account, 0, len(accounts))
		for _, acc := range accounts {
			status := "Deployment up to date"
			needsDeployment, err := accountSrvc.NeedsDeployment(ctx, acc.Name)
			if err != nil {
				status = fmt.Sprintf("error getting status: %s", err.Error())
			} else if needsDeployment {
				status = "Needs deployment"
			}
			templateAccounts = append(templateAccounts, templates.Account{AccountName: acc.Name, AccountId: acc.AwsAccountId, UpdateStatus: status})
		}
		data := templates.AdminData{
			Navbar:   templates.Navbar{Username: user.Username, HasAdmin: user.Superuser},
			Accounts: templateAccounts,
		}
		if err := templates.AdminTemplate(w, data); err != nil {
			sendError(w, r, err)
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
			cookie, err := r.Cookie(authCookie)
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

func superOnlyMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := getUser(r)
			if !user.Superuser {
				sendUnathorized(w, r, errors.New("only superusers can use this!"))
				return
			}
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

func sendUnathorized(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusUnauthorized)
	log.Println(err)
	render.JSON(w, r, struct {
		Error string `json:"error"`
	}{err.Error()})
}

func sendError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	log.Println(err)
	render.JSON(w, r, struct {
		Error string `json:"error"`
	}{err.Error()})
}
