package webui

import (
	"context"
	"log"
	"net/http"
	"slices"
	"time"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
)

const cookieName = "AwsLoginAuthCookie"

type WebUi struct {
	http.ServeMux
	store storage.Storage
	idp   auth.AuthMethod
	token auth.LoginToken
	sts   aws.StsClient
}

func NewWebUi(token auth.LoginToken, store storage.Storage, idp auth.AuthMethod, sts aws.StsClient) *WebUi {
	ui := WebUi{store: store, idp: idp, token: token, sts: sts}
	guard := authGuard{token: token, idp: idp}
	ui.Handle("GET /accounts/{accountId}/roles", guard.guard(ui.handleRoles))
	ui.Handle("GET /accounts/{accountId}/console", guard.guard(ui.handleConsoleLogin))
	ui.Handle("GET /accounts/{accountId}/credentials", guard.guard(ui.handleRoles))
	ui.Handle("GET /accounts/", guard.guard(ui.handleAccounts))
	ui.Handle("GET /login/", guard.optional(ui.handleLogin))
	ui.Handle("GET /expired/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "expired.html", templates.TemplateData("Expired"))
	}))
	ui.Handle("GET /logout/", guard.optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := userFromRequest(r)
		if ok {
			c, _ := r.Cookie(cookieName)
			c.MaxAge = -1
			c.Path = "/"
			http.SetCookie(w, c)
		}
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})))
	ui.Handle("GET /oauth2/idpresponse/", http.HandlerFunc(ui.handleCallback))
	ui.Handle("GET /", guard.optional(handleIndex))
	return &ui
}
func (ui *WebUi) handleLogin(w http.ResponseWriter, r *http.Request) {
	_, ok := userFromRequest(r)
	if ok {
		// already logged
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	http.Redirect(w, r, ui.idp.RedirectUrl(), http.StatusTemporaryRedirect)
}

func (ui *WebUi) handleCallback(w http.ResponseWriter, r *http.Request) {
	info, err := ui.idp.HandleCallback(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	usr, err := ui.store.GetUserByUsername(r.Context(), info.Username)
	if err == storage.ErrUserNotFound {
		usr.Email = info.Email
		usr.Username = info.Username
		usr, err = ui.store.PutUser(r.Context(), usr, false)
		log.Printf("created user [%s]\n", usr.Username)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info.Id = usr.Id

	access_token, err := ui.token.SignToken(*info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	expiredTime := time.Now().Add(time.Hour * 8)
	cookie := http.Cookie{
		Name:     cookieName,
		Value:    access_token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiredTime,
		MaxAge:   int((time.Hour * 8) / time.Second),
	}
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (ui *WebUi) handleAccounts(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	page := r.URL.Query().Get("page")
	listAccounts, err := ui.store.ListAccountsForUser(r.Context(), user.Id, pointerString(page))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := templates.TemplateData("Accounts")
	data.Logged = true
	data.User = user
	data.Accounts = listAccounts.Accounts
	data.StartToken = toString(listAccounts.StartToken)
	renderTemplate(w, "accounts.html", data)
}

func (ui *WebUi) handleConsoleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountId := r.PathValue("accountId")
	roleName := aws.AwsRole(r.URL.Query().Get("roleName")).RealName()
	user, _ := userFromRequest(r)

	acc, err := ui.store.GetAccountById(ctx, accountId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	listPerms, err := ui.store.ListUserPermissions(ctx, user.Id, accountId, storage.UserPermissionAssume, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// it should be only one perm
	if len(listPerms.UserPermissions) != 1 {
		http.Error(w, "no permission in this account", http.StatusUnauthorized)
		return
	}

	if !slices.Contains(listPerms.UserPermissions[0].Value, roleName) {
		http.Error(w, "cannot assume this role", http.StatusUnauthorized)
		return
	}

	arn := acc.ArnForRole(roleName)
	url, err := aws.GenerateSigninUrl(ctx, ui.sts, arn, user.Username, "https://aws.amazon.com/console/")
	if err != nil {
		http.Error(w, "unable to generate url "+err.Error(), http.StatusInternalServerError)
		return
	}
	// redirect to url
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (ui *WebUi) handleRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountId := r.PathValue("accountId")

	user, _ := userFromRequest(r)

	acc, err := ui.store.GetAccountById(ctx, accountId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	listPerms, err := ui.store.ListUserPermissions(ctx, user.Id, accountId, storage.UserPermissionAssume, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// it should be only one perm
	if len(listPerms.UserPermissions) != 1 {
		http.Error(w, "no permission in this account", http.StatusOK)
		return
	}
	roles := []templates.Role{}
	for _, role := range listPerms.UserPermissions[0].Value {
		roles = append(roles, templates.Role{Arn: acc.ArnForRole(role), Name: aws.AwsRole(role).String(), AccountId: acc.Id})
	}
	data := templates.TemplateData("Roles")
	data.Logged = true
	data.User = user
	data.Roles = roles
	renderTemplate(w, "roles.html", data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	user, ok := userFromRequest(r)
	data := templates.TemplateData("Home")
	data.Logged = ok
	data.User = user
	renderTemplate(w, "index.html", data)
}

type userContext struct{}

var UserContext userContext

func userFromRequest(r *http.Request) (*auth.UserInfo, bool) {
	usr, ok := r.Context().Value(UserContext).(*auth.UserClaims)
	if ok {
		return &usr.UserInfo, true
	}
	return &auth.UserInfo{}, false
}

type authGuard struct {
	token auth.LoginToken
	idp   auth.AuthMethod
}

func (g *authGuard) optional(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err == http.ErrNoCookie {
			h.ServeHTTP(w, r)
			return
		}
		if err != nil {
			http.Error(w, "error while extracting cookies", http.StatusInternalServerError)
			log.Println(err)
			return
		}
		user, err := g.token.Validate(cookie.Value)
		if err != nil {
			http.Error(w, "unable to validate authentication cookie", http.StatusUnauthorized)
			log.Println(err)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserContext, user)))
	})
}

func (g *authGuard) guard(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			renderTemplate(w, "login.html", templates.TemplateData("Login"))
			return
		}
		user, err := g.token.Validate(cookie.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if user.ExpiresAt.Before(time.Now().UTC()) {
			// expired
			cookie.MaxAge = -1
			cookie.Path = "/"
			http.SetCookie(w, cookie)
			http.Redirect(w, r, "/expired", http.StatusOK)
			return
		}
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), UserContext, user)))
	})
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	err := templates.RenderPage(w, name, data)
	if err != nil {
		log.Println(err)
	}
}

func toString(v *string) string {
	if v != nil {
		return *v
	}
	return ""
}

func pointerString(v string) *string {
	if v != "" {
		return &v
	}
	return nil
}
