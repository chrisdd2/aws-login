package v2

import (
	"embed"
	"fmt"
	"net/http"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services"
	"github.com/chrisdd2/aws-login/internal/services/account"
	"github.com/chrisdd2/aws-login/store"
	"github.com/chrisdd2/aws-login/webui/v2/middleware"
	"github.com/chrisdd2/aws-login/webui/v2/pages"
	"github.com/go-chi/chi/v5"
)

//go:embed static
var staticFiles embed.FS

const authCookie = "aws-login-cookie"

type Router struct {
	basePath     string
	cfg          *appconfig.AppConfig
	tokenSvc     services.TokenService
	auths        []services.AuthService
	roles        services.RolesService
	accounts     account.AccountService
	store        store.Store
	rootPage     *RootPage
	loginPage    *pages.LoginPage
	rolesPage    *pages.RolesPage
	accountsPage *pages.AccountsPage
	configPage   *pages.ConfigPage
}

func NewRouter(
	basePath string,
	cfg *appconfig.AppConfig,
	tokenSvc services.TokenService,
	auths []services.AuthService,
	rolesSvc services.RolesService,
	accountsSvc account.AccountService,
	storeSvc store.Store,
) (*Router, error) {
	rootPage, err := NewRootPage(basePath, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create root page: %w", err)
	}

	loginPage, err := pages.NewLoginPage(basePath, cfg, auths, rootPage)
	if err != nil {
		return nil, fmt.Errorf("failed to create login page: %w", err)
	}

	rolesPage, err := pages.NewRolesPage(basePath, cfg, rolesSvc, storeSvc, rootPage)
	if err != nil {
		return nil, fmt.Errorf("failed to create roles page: %w", err)
	}

	accountsPage, err := pages.NewAccountsPage(basePath, cfg, accountsSvc, rootPage)
	if err != nil {
		return nil, fmt.Errorf("failed to create accounts page: %w", err)
	}

	configPage, err := pages.NewConfigPage(basePath, cfg, storeSvc, rootPage)
	if err != nil {
		return nil, fmt.Errorf("failed to create config page: %w", err)
	}

	return &Router{
		basePath:     basePath,
		cfg:          cfg,
		tokenSvc:     tokenSvc,
		auths:        auths,
		roles:        rolesSvc,
		accounts:     accountsSvc,
		store:        storeSvc,
		rootPage:     rootPage,
		loginPage:    loginPage,
		rolesPage:    rolesPage,
		accountsPage: accountsPage,
		configPage:   configPage,
	}, nil
}

func (r *Router) Handler() chi.Router {
	router := chi.NewMux()
	router.Use(func(h http.Handler) http.Handler {
		return http.StripPrefix(r.basePath, h)
	})
	router.Get("/login", r.loginPage.Render)
	router.Post("/login", r.handleLoginPost)

	// strip the path
	router.Mount("/static", http.FileServerFS(staticFiles))

	loggedIn := router.With(r.authMiddleware)
	loggedIn.Mount("/roles", r.rolesPage.Router())

	superuser := loggedIn.With(func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			usr := middleware.GetUser(r)
			if !usr.Superuser {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		})
	})
	superuser.Mount("/accounts", r.accountsPage.Router())
	superuser.Mount("/config", r.configPage.Router())

	return router
}

func (r *Router) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		cookie, err := req.Cookie(authCookie)
		if err != nil {
			http.Redirect(w, req, r.basePath+"/login", http.StatusSeeOther)
			return
		}

		info, err := r.tokenSvc.Validate(req.Context(), cookie.Value)
		if err != nil {
			http.Redirect(w, req, r.basePath+"/login?error=invalid_cookie", http.StatusSeeOther)
			return
		}

		ctx := middleware.SetUser(req.Context(), info)
		next.ServeHTTP(w, req.WithContext(ctx))
	})
}

func (r *Router) handleLoginPost(w http.ResponseWriter, req *http.Request) {
	loginType := req.URL.Query().Get("type")

	// Check for IdP callbacks
	for _, idp := range r.auths {
		if idp.Details().Name == loginType {
			idp.Login(w, req)
			return
		}
	}

	// Admin login
	if loginType == "userpass" {
		req.ParseForm()
		username := req.Form.Get("username")
		password := req.Form.Get("password")

		if username == r.cfg.Auth.AdminUsername && password == r.cfg.Auth.AdminPassword {
			accessToken, _ := r.tokenSvc.Create(req.Context(), &services.UserInfo{
				Username:     username,
				FriendlyName: friendlyName(username),
				Superuser:    true,
				LoginType:    "userpass",
			}, false)

			secure := r.cfg.IsProduction()
			r.setAuthCookie(w, accessToken, secure)
			http.Redirect(w, req, "/", http.StatusTemporaryRedirect)
			return
		}

		http.Redirect(w, req, r.basePath+"/login?error=wrong_credentials", http.StatusSeeOther)
		return
	}

	http.Redirect(w, req, r.basePath+"/login", http.StatusSeeOther)
}

func (r *Router) setAuthCookie(w http.ResponseWriter, token string, secure bool) {
	cookie := http.Cookie{
		Name:     authCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int((8 * time.Hour) / time.Second),
		Expires:  time.Now().UTC().Add(8 * time.Hour),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
	}
	http.SetCookie(w, &cookie)
}

func (r *Router) handleHome(w http.ResponseWriter, req *http.Request) {
	// Home page - redirect to roles (main page for logged in users)
}

func (r *Router) handleLogout(w http.ResponseWriter, req *http.Request) {
	user := middleware.GetUser(req)
	if user == nil {
		http.Redirect(w, req, r.basePath+"/login", http.StatusTemporaryRedirect)
		return
	}

	// Clear the cookie
	cookie, _ := req.Cookie(authCookie)
	if cookie != nil {
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}

	// Try to logout from IdP
	rootUrl := r.cfg.RootUrl
	if rootUrl == "" {
		rootUrl = "/"
	}

	for _, idp := range r.auths {
		if user.LoginType == idp.Details().Name {
			http.Redirect(w, req, idp.LogoutUrl(rootUrl, user.IdpToken), http.StatusTemporaryRedirect)
			return
		}
	}

	// For userpass or no IdP, redirect to login
	http.Redirect(w, req, r.basePath+"/login", http.StatusTemporaryRedirect)
}

func friendlyName(email string) string {
	for i, c := range email {
		if c == '@' {
			return email[:i]
		}
	}
	return email
}
