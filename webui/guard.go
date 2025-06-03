package webui

import (
	"net/http"
	"time"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
	"fmt"
)

func guard(token auth.LoginToken) echo.MiddlewareFunc {

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie(cookieName)
			if err != nil {
				c.Render(http.StatusOK, "login.html", templates.TemplateData(nil, "Login"))
				return nil
			}
			user, err := token.Validate(cookie.Value)
			if err != nil {
				return fmt.Errorf("guard [token.Validate] [%w]", err)
			}
			if user.ExpiresAt.Before(time.Now().UTC()) {
				// expired
				cookie.MaxAge = -1
				cookie.Path = "/"
				c.SetCookie(cookie)
				c.Redirect(http.StatusOK, "/expired")
				return nil
			}
			c.Set("user", user)
			return next(c)
		}
	}
}

func optionalGuard(token auth.LoginToken) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			cookie, err := c.Cookie(cookieName)
			if err == http.ErrNoCookie {
				return next(c)
			}
			user, err := token.Validate(cookie.Value)
			if err != nil {
				return fmt.Errorf("optionalGuard [token.Validate] [%w]", err)
			}
			if user.ExpiresAt.Before(time.Now().UTC()) {
				// expired
				cookie.MaxAge = -1
				cookie.Path = "/"
				c.SetCookie(cookie)
				c.Redirect(http.StatusOK, "/expired")
				return nil
			}
			c.Set("user", user)
			return next(c)
		}
	}
}

func userFromRequest(ctx echo.Context) (*auth.UserInfo, bool) {
	usr, ok := ctx.Get("user").(*auth.UserClaims)
	if ok {
		return &usr.UserInfo, true
	}
	return nil, false
}
