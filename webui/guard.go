package webui

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/webui/templates"
)

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
			renderTemplate(w, "login.html", templates.TemplateData(nil, "Login"))
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

type userContext struct{}

var UserContext userContext

func userFromRequest(r *http.Request) (*auth.UserInfo, bool) {
	usr, ok := r.Context().Value(UserContext).(*auth.UserClaims)
	if ok {
		return &usr.UserInfo, true
	}
	return nil, false
}
