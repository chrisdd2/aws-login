package webui

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/chrisdd2/aws-login/services"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const authCookie = "aws-login-cookie"

func Router(tokenSvc services.TokenService, authSvc services.AuthService) chi.Router {
	r := chi.NewRouter()
	r.Get("/login", func(w http.ResponseWriter, r *http.Request) {
		_ = r.URL.Query().Get("error")
		loginType := r.URL.Query().Get("type")
		switch loginType {
		case "keycloak":
			http.Redirect(w, r, authSvc.RedirectUrl(), http.StatusTemporaryRedirect)
		default:
			http.ServeFile(w, r, "webui/login.html")
		}
	})
	r.HandleFunc(authSvc.CallbackEndpoint(), func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		info, err := authSvc.CallbackHandler(r)
		if err != nil {
			render.Status(r, http.StatusUnauthorized)
			log.Println(err)
			render.JSON(w, r, err)
		}
		accessToken, err := tokenSvc.Create(ctx, &services.UserInfo{Username: info.Username, Email: info.Email})
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
	r.With(guardMiddleware(tokenSvc)).Mount("/", http.FileServer(http.Dir("webui")))
	return r
}

type userCtxKey struct{}

var UserCtxKey = userCtxKey{}

func guardMiddleware(tokenService services.TokenService) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("aws-login-cookie")
			if err != nil {
				http.Redirect(w, r, "/login?error=missing_cookie", http.StatusSeeOther)
				return
			}
			info, err := tokenService.Validate(r.Context(), cookie.Value)
			if err != nil {
				http.Redirect(w, r, "/login?error=invalid_cookie", http.StatusSeeOther)
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), UserCtxKey, info))
			next.ServeHTTP(w, r)
		})
	}
}
