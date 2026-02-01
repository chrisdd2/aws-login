package webui

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services"
	"github.com/chrisdd2/aws-login/internal/services/account"
	"github.com/chrisdd2/aws-login/store"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
	"sigs.k8s.io/yaml"
)

var ErrNotSupported = errors.New("not supported")

const authCookie = "aws-login-cookie"

func loginErrorString(queryParams url.Values) string {
	errorValue := queryParams.Get("error")
	if errorValue == "" {
		return ""
	}
	switch errorValue {
	case "invalid_cookie":
		return "Authentication cookie is invalid, log out and retry"
	case "user_not_found":
		return fmt.Sprintf("User [%s] not found in database.\nContact an administrator", queryParams.Get("username"))
	case "wrong_credentials":
		return "Invalid username/password"
	default:
		return fmt.Sprintf("Interval server error [%s]", queryParams.Get("message"))
	}
}

func Router(
	shutdownCtxCancel context.CancelCauseFunc,
	tokenSvc services.TokenService,
	authSvcs []services.AuthService,
	rolesSvc services.RolesService,
	accountSrvc account.AccountService,
	storageSvc store.Store,
	cfg appconfig.AppConfig,
) chi.Router {

	// superUserRole := cfg.Storage.Sync.Keycloak.SuperUserRole
	hasAdminLogin := cfg.Auth.AdminPassword != "" && cfg.Auth.AdminUsername != ""
	secureCookies := cfg.IsProduction()

	r := chi.NewRouter()
	// font awesome ruins me
	r.Mount("/webfonts", http.FileServerFS(templates.Static))
	r.Mount("/static", http.FileServerFS(templates.Static))
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		loginType := query.Get("type")
		for _, idp := range authSvcs {
			if idp.Details().Name != loginType {
				continue
			}
			idp.Login(w, r)
			return
		}
		data := templates.LoginData{HasAdminPrompt: hasAdminLogin, AppName: cfg.Name, ErrorString: loginErrorString(query)}
		for _, idp := range authSvcs {
			name := idp.Details().Name
			prettyName := strings.ToUpper(name[0:1]) + name[1:]
			data.LoginType = append(data.LoginType, struct {
				Name string
				Desc string
			}{Name: idp.Details().Name, Desc: fmt.Sprintf("Sign in with %s", prettyName)})
		}
		if err := templates.LoginTemplate(w, data); err != nil {
			sendError(w, r, fmt.Errorf("templates.LoginTemplate: %w", err))
		}
	})
	r.Post("/login", func(w http.ResponseWriter, r *http.Request) {
		urlParams := r.URL.Query()
		loginType := urlParams.Get("type")
		if loginType == "userpass" {
			r.ParseForm()
			username := r.Form.Get("username")
			password := r.Form.Get("password")
			if !(username == cfg.Auth.AdminUsername && password == cfg.Auth.AdminPassword) {
				redirectWithParams(w, r, "/login", map[string]string{"error": "wrong_credentials"}, http.StatusSeeOther)
				return
			}
			accessToken, _ := tokenSvc.Create(r.Context(), &services.UserInfo{Username: username, FriendlyName: friendlyName(username), Superuser: true, LoginType: "userpass"}, false)
			sendAccessToken(w, r, accessToken, secureCookies)
			return
		}
		if err := templates.LoginTemplate(w, templates.LoginData{AppName: cfg.Name, HasAdminPrompt: hasAdminLogin, ErrorString: loginErrorString(urlParams)}); err != nil {
			sendError(w, r, fmt.Errorf("templates.LoginTemplate: %w", err))
		}
	})

	for _, idp := range authSvcs {
		// idp response
		details := idp.Details()
		r.HandleFunc(details.Endpoint, func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			info, err := idp.CallbackHandler(r)
			if err != nil {
				sendUnathorized(w, r, err)
				return
			}
			accessToken, err := tokenSvc.Create(ctx, &services.UserInfo{Username: info.Username, FriendlyName: info.FriendlyName, LoginType: details.Name, IdpToken: info.IdpToken}, true)
			if err == store.ErrResourceNotFound {
				redirectWithParams(w, r, "/login", map[string]string{"error": "user_not_found", "username": info.Username}, http.StatusSeeOther)
				return
			}
			if err != nil {
				sendUnathorized(w, r, err)
				return
			}
			sendAccessToken(w, r, accessToken, secureCookies)
		})

	}
	loggedIn := r.With(guardMiddleware(tokenSvc))
	mainHandler := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)
		roles, err := rolesSvc.ListRoles(ctx, user.Username)
		if err != nil {
			sendError(w, r, fmt.Errorf("rolesSvc.ListRoles: %w", err))
			return
		}
		templateRoles := []templates.Role{}
		for role := range roles {
			accId, err := role.AccountId(ctx, storageSvc)
			if err != nil {
				sendError(w, r, fmt.Errorf("role.AccountId: %w", err))
				return
			}
			templateRoles = append(templateRoles, templates.Role{
				AccountName:    role.AccountName,
				AccountId:      accId,
				RoleName:       role.RoleName,
				HasCredentials: slices.Contains(role.Permissions, store.RolePermissionCredentials),
				HasConsole:     slices.Contains(role.Permissions, store.RolePermissionConsole),
			})
		}
		data := templates.RolesData{
			Navbar: templates.Navbar{AppName: cfg.Name, Username: user.FriendlyName, HasAdmin: user.Superuser},
			Roles:  templateRoles,
		}
		if err := templates.RolesTemplate(w, data); err != nil {
			sendError(w, r, fmt.Errorf("templates.RolesTemplate: %w", err))
		}
	}
	loggedIn.Get("/", mainHandler)
	loggedIn.Post("/", mainHandler)
	loggedIn.Get("/logout", func(w http.ResponseWriter, r *http.Request) {
		user := getUser(r)

		cookie, _ := r.Cookie(authCookie)
		if cookie != nil {
			cookie.MaxAge = -1
			http.SetCookie(w, cookie)
		}
		rootUrl := cfg.RootUrl
		if rootUrl == "" {
			rootUrl = "/"
		}
		for _, idp := range authSvcs {
			if user.LoginType == idp.Details().Name {
				http.Redirect(w, r, idp.LogoutUrl(rootUrl, user.IdpToken), http.StatusTemporaryRedirect)
				return
			}
		}
		// its userpass, redirect to main
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})

	statusCache := StatusCache{accountsSvc: accountSrvc, in: sync.Map{}}
	loggedIn.With(superOnlyMiddleware()).Get("/admin", func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)

		accounts, err := accountSrvc.ListAccounts(ctx)
		if err != nil {
			sendError(w, r, fmt.Errorf("accountSrvc.ListAccounts: %w", err))
			return
		}
		templateAccounts := make([]templates.Account, 0, len(accounts))
		for _, acc := range accounts {
			status, err := statusCache.Status(ctx, acc.Name)
			if err != nil {
				sendError(w, r, fmt.Errorf("statusCache.Status: %w", err))
				return
			}
			templateAccounts = append(templateAccounts, templates.Account{
				AccountName:  acc.Name,
				AccountId:    acc.AwsAccountId,
				UpdateStatus: deploymentStatusMessage(status),
				HasStack:     status.StackExists,
				HasDeploy:    !status.NeedsBootstrap,
			})
		}
		data := templates.AccountsData{
			Navbar:   templates.Navbar{AppName: cfg.Name, Username: user.FriendlyName, HasAdmin: user.Superuser},
			Accounts: templateAccounts,
		}
		if err := templates.AccountsTemplate(w, data); err != nil {
			sendError(w, r, fmt.Errorf("templates.AccountsTemplate: %w", err))
		}
	})
	loggedIn.With(superOnlyMiddleware()).Route("/config", func(r chi.Router) {
		r.Get("/shutdown", func(w http.ResponseWriter, r *http.Request) {
			render.JSON(w, r, struct {
				Message string `json:"message"`
			}{Message: "shutting down"})
			shutdownCtxCancel(errors.New("user_request"))
		})
		r.Post("/import", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			file, _, err := r.FormFile("file")
			if err != nil {
				sendError(w, r, fmt.Errorf("r.FormFile: %w", err))
				return
			}
			defer file.Close()
			fs := store.FileStore{}
			if err := fs.LoadYaml(file); err != nil {
				sendError(w, r, fmt.Errorf("fs.LoadYaml: %w", err))
				return
			}
			changes, err := store.Import(ctx, storageSvc, &fs.MemoryStore)
			if err != nil {
				sendError(w, r, fmt.Errorf("store.Import: %w", err))
				return
			}
			configHandler(w, r, storageSvc, &cfg, changes)
		})
		r.Get("/export", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			st, err := store.Export(ctx, storageSvc)
			buf, err := yaml.Marshal(st)
			if err != nil {
				sendError(w, r, fmt.Errorf("yaml.Marshal: %w", err))
				return
			}

			w.Header().Add("Content-Type", "application/yaml")
			w.Write(buf)
		})
		r.Get("/sync", func(w http.ResponseWriter, r *http.Request) {
			configHandler(w, r, storageSvc, &cfg, nil)
		})
		r.Get("/", func(w http.ResponseWriter, r *http.Request) {
			configHandler(w, r, storageSvc, &cfg, nil)
		})
	})
	loggedIn.Route("/account", func(r chi.Router) {
		r.Get("/console", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			user := getUser(r)

			query := r.URL.Query()
			account := query.Get("account")
			role := query.Get("role")
			if account == "" || role == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			url, err := rolesSvc.Console(ctx, account, role, user.Username)
			if err != nil {
				if errors.Is(err, services.ErrRoleUnauthorized) {
					sendUnathorized(w, r, err)
					return
				}
				sendError(w, r, fmt.Errorf("rolesSvc.Console: %w", err))
				return
			}
			http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		})
		r.Get("/credentials", func(w http.ResponseWriter, r *http.Request) {
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

			creds, err := rolesSvc.Credentials(ctx, account, role, user.Username)
			if err != nil {
				if errors.Is(err, services.ErrRoleUnauthorized) {
					sendUnathorized(w, r, err)
					return
				}
				sendError(w, r, fmt.Errorf("rolesSvc.Credentials: %w", err))
				return
			}

			if format == "" {
				format = "linux"
			}
			render.PlainText(w, r, creds.Format(format))
		})

		g := r.With(superOnlyMiddleware())
		r.Get("/bootstrap_template", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			account := r.URL.Query().Get("account")
			if account == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			templateString, err := accountSrvc.BootstrapTemplate(ctx, account)
			if err != nil {
				sendError(w, r, fmt.Errorf("accountSrvc.BootstrapTemplate: %w", err))
				return
			}
			render.PlainText(w, r, templateString)
		})
		r.Get("/status", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			account := r.URL.Query().Get("account")
			if account == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			statusCache.Refresh(ctx, account)
			http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
		})
		g.Get("/deploy", func(w http.ResponseWriter, r *http.Request) {
			user := getUser(r)
			ctx := r.Context()
			account := r.URL.Query().Get("account")
			if account == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := accountSrvc.Deploy(ctx, user.Username, account); err != nil {
				sendError(w, r, fmt.Errorf("accountSrvc.Deploy: %w", err))
				return
			}
			redirectWithParams(w, r, "/account/watch", map[string]string{"account": account}, http.StatusTemporaryRedirect)
			// refreh cache
			statusCache.Refresh(ctx, account)
		})
		g.Get("/watch", func(w http.ResponseWriter, r *http.Request) {
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
				sendError(w, r, fmt.Errorf("accountSrvc.StackUpdates: %w", err))
				return
			}
			if err := templates.WatchTemplate(w, templates.WatchData{
				Navbar: templates.Navbar{AppName: cfg.Name, Username: user.FriendlyName, HasAdmin: user.Superuser},
				Events: events,
			}); err != nil {
				sendError(w, r, fmt.Errorf("templates.WatchTemplate: %w", err))
			}

		})
		g.Get("/destroy", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			query := r.URL.Query()
			account := query.Get("account")
			if account == "" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			user := getUser(r)
			stackId, err := accountSrvc.DestroyStack(ctx, account, user.Username)
			if err != nil {
				sendError(w, r, fmt.Errorf("accountSrvc.DestroyStack: %w", err))
				return
			}
			redirectWithParams(w, r, "/account/watch", map[string]string{"account": account, "stackId": stackId}, http.StatusTemporaryRedirect)
			// refreh cache
			statusCache.Refresh(ctx, account)
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
			cookie, err := r.Cookie(authCookie)
			if err != nil {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			info, err := tokenService.Validate(r.Context(), cookie.Value)
			if err != nil {
				redirectWithParams(w, r, "/login", map[string]string{"error": "invalid_cookie", "message": err.Error()}, http.StatusSeeOther)
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
				sendUnathorized(w, r, account.ErrNoPermission)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func sendAccessToken(w http.ResponseWriter, r *http.Request, accessToken string, secure bool) {
	cookie := http.Cookie{
		Name:     authCookie,
		Value:    accessToken,
		Path:     "/",
		MaxAge:   int((time.Hour * 8) / time.Second),
		Expires:  time.Now().UTC().Add(time.Hour * 8),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func sendUnathorized(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusUnauthorized)
	render.JSON(w, r, struct {
		Error string `json:"error"`
	}{err.Error()})
}

func sendError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	slog.Debug("http", "error", err)
	render.JSON(w, r, struct {
		Error string `json:"error"`
	}{err.Error()})
}

func deploymentStatusMessage(d account.DeploymentStatus) string {
	if d.NeedsBootstrap {
		return "Needs bootstrap (manual)"
	}
	if d.StackExists {
		if d.NeedsUpdate {
			return "Needs sync"
		} else {
			return "Up to date"
		}
	}
	return "Needs first deployment"
}

func redirectWithParams(w http.ResponseWriter, r *http.Request, redirectUrl string, params map[string]string, statusCode int) {
	vals := url.Values{}
	for k, v := range params {
		vals.Add(k, v)
	}
	http.Redirect(w, r, fmt.Sprintf("%s?%s", redirectUrl, vals.Encode()), statusCode)
}

type StatusCache struct {
	accountsSvc account.AccountService
	in          sync.Map
}

func (s *StatusCache) Status(ctx context.Context, accountName string) (account.DeploymentStatus, error) {
	statusV, ok := s.in.Load(accountName)
	if ok {
		return statusV.(account.DeploymentStatus), nil
	}
	return s.Refresh(ctx, accountName)
}

func (s *StatusCache) Refresh(ctx context.Context, accountName string) (account.DeploymentStatus, error) {
	status, err := s.accountsSvc.DeploymentStatus(ctx, accountName)
	if err != nil {
		return account.DeploymentStatus{}, err
	}
	s.in.Store(accountName, status)
	return status, err
}

func friendlyName(email string) string {
	before, _, _ := strings.Cut(email, "@")
	return before
}

func configHandler(w http.ResponseWriter, r *http.Request, storageSvc store.Store, cfg *appconfig.AppConfig, changes []store.Change) {
	ctx := r.Context()
	user := getUser(r)
	ms, err := store.Export(ctx, storageSvc)
	if err != nil {
		sendError(w, r, fmt.Errorf("store.Export: %w", err))
		return
	}
	data := templates.ConfigurationData{
		Navbar:  templates.Navbar{AppName: cfg.Name, Username: user.FriendlyName, HasAdmin: user.Superuser},
		Store:   ms,
		Changes: changes,
	}
	if err := templates.ConfigurationTemplate(w, data); err != nil {
		sendError(w, r, fmt.Errorf("templates.ConfigurationTemplate: %w", err))
	}
}
