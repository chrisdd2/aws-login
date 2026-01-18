package webui

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	"github.com/chrisdd2/aws-login/internal/services/storage"
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
	storageSvc storage.Storage,
	cfg appconfig.AppConfig,
	ev storage.Eventer,
	syncer storage.SyncStorer,
	superUserRole string,
) chi.Router {

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
			sendError(w, r, err)
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
			ev.Publish(r.Context(), "user_login", map[string]string{"username": username, "login_type": loginType})
			sendAccessToken(w, r, accessToken, secureCookies)
			return
		}
		if err := templates.LoginTemplate(w, templates.LoginData{AppName: cfg.Name, HasAdminPrompt: hasAdminLogin, ErrorString: loginErrorString(urlParams)}); err != nil {
			sendError(w, r, err)
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
			if err == storage.ErrUserNotFound {
				redirectWithParams(w, r, "/login", map[string]string{"error": "user_not_found", "username": info.Username}, http.StatusSeeOther)
				return
			}
			if err != nil {
				sendUnathorized(w, r, err)
				return
			}
			ev.Publish(ctx, "user_login", map[string]string{"username": info.Username, "login_type": details.Name})
			sendAccessToken(w, r, accessToken, secureCookies)
		})

	}
	loggedIn := r.With(guardMiddleware(tokenSvc))
	mainHandler := func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		user := getUser(r)
		var roles []appconfig.RoleUserAttachment
		var err error
		roles, err = rolesSvc.UserPermissions(ctx, user.Username, "", "")
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
				HasCredentials: slices.Contains(role.Permissions, appconfig.RolePermissionCredentials),
				HasConsole:     slices.Contains(role.Permissions, appconfig.RolePermissionConsole),
			})
		}
		data := templates.RolesData{
			Navbar: templates.Navbar{AppName: cfg.Name, Username: user.FriendlyName, HasAdmin: user.Superuser},
			Roles:  templateRoles,
		}
		if err := templates.RolesTemplate(w, data); err != nil {
			sendError(w, r, err)
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
			sendError(w, r, err)
			return
		}
		templateAccounts := make([]templates.Account, 0, len(accounts))
		for _, acc := range accounts {
			status, err := statusCache.Status(ctx, acc.Name)
			if err != nil {
				sendError(w, r, err)
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
			sendError(w, r, err)
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
			user := getUser(r)
			file, _, err := r.FormFile("file")
			if err != nil {
				sendError(w, r, err)
				return
			}
			defer file.Close()
			fs := storage.InMemoryStore{}
			buf, err := io.ReadAll(file)
			if err != nil {
				sendError(w, r, fmt.Errorf("io.ReadAll: %w", err))
				return
			}
			if err := yaml.UnmarshalStrict(buf, &fs, yaml.DisallowUnknownFields); err != nil {
				sendError(w, r, fmt.Errorf("yaml.UnmarshalStrict: %w", err))
			}
			importable, ok := storageSvc.(storage.Importable)
			if !ok {
				sendError(w, r, ErrNotSupported)
				return
			}
			changes, err := storage.ImportAll(ctx, importable, &fs, false)
			if err != nil {
				sendError(w, r, err)
				return
			}

			ev.Publish(ctx, "config_import", map[string]string{"username": user.Username})
			configHandler(w, r, storageSvc, &cfg, changes)
		})
		r.Get("/export", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			user := getUser(r)
			printable, ok := storageSvc.(storage.Printable)
			if !ok {
				printable = storage.NoopStorage{}
			}
			st, err := printable.Display(ctx)
			if err != nil {
				sendError(w, r, err)
				return
			}
			buf, err := yaml.Marshal(st)
			if err != nil {
				sendError(w, r, err)
				return
			}
			ev.Publish(ctx, "config_export", map[string]string{"username": user.Username})

			w.Header().Add("Content-Type", "application/yaml")
			w.Write(buf)
		})
		r.Get("/reload", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			reloadable, ok := storageSvc.(storage.Reloadable)
			if !ok {
				reloadable = storage.NoopStorage{}
			}
			if err := reloadable.Reload(ctx); err != nil {
				sendError(w, r, err)
			}
			slog.Info("reloaded config", "source", "admin_page")
			http.Redirect(w, r, "/config", http.StatusTemporaryRedirect)
		})
		r.Get("/sync", func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			importable, ok := storageSvc.(storage.Importable)
			if syncer == nil || !ok {
				sendError(w, r, ErrNotSupported)
				return
			}
			im, err := storage.Sync(ctx, syncer, storageSvc, superUserRole)
			if err != nil {
				sendError(w, r, err)
				return
			}
			changesUsers, err := storage.ImportUsers(ctx, importable, im.Users, true)
			if err != nil {
				sendError(w, r, err)
				return
			}
			changesUserAttachments, err := storage.ImportRoleUserAttachments(ctx, importable, im.RoleUserAttachments, true)
			if err != nil {
				sendError(w, r, err)
				return
			}
			configHandler(w, r, storageSvc, &cfg, append(changesUsers, changesUserAttachments...))
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
				sendError(w, r, err)
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
				sendError(w, r, err)
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
				sendError(w, r, err)
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
				sendError(w, r, err)
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
				sendError(w, r, err)
				return
			}
			if err := templates.WatchTemplate(w, templates.WatchData{
				Navbar: templates.Navbar{AppName: cfg.Name, Username: user.FriendlyName, HasAdmin: user.Superuser},
				Events: events,
			}); err != nil {
				sendError(w, r, err)
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
				sendError(w, r, err)
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

func configHandler(w http.ResponseWriter, r *http.Request, storageSvc storage.Storage, cfg *appconfig.AppConfig, changes []storage.Change) {
	ctx := r.Context()
	user := getUser(r)
	printable, ok := storageSvc.(storage.Printable)
	if !ok {
		printable = storage.NoopStorage{}
	}
	st, err := printable.Display(ctx)
	if err != nil {
		sendError(w, r, err)
		return
	}
	data := templates.ConfigurationData{
		Navbar:  templates.Navbar{AppName: cfg.Name, Username: user.FriendlyName, HasAdmin: user.Superuser},
		Store:   st,
		Changes: changes,
	}
	if err := templates.ConfigurationTemplate(w, data); err != nil {
		sendError(w, r, err)
	}
}
