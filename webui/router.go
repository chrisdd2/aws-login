package webui

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/chrisdd2/aws-login/webui/templates/css"
	"github.com/labstack/echo/v4"
)

const cookieName = "AwsLoginAuthCookie"
const tokenExpirationTime = time.Hour * 8

func Router(e *echo.Echo, auth auth.AuthMethod, store *storage.StorageService, token auth.LoginToken, stsCl aws.StsClient) {

	accountsRouter(e, token, store, stsCl)
	usersRouter(e, store, token)
	e.GET("/login/", handleLogin(token, store, auth))
	e.GET("/logout/", handleLogout(token), guard(token))
	e.GET("/expired/", handleExpired())
	e.GET("/oauth2/idpresponse/", handleOAuth2IdpResponse(auth, store, token))
	e.GET("/admin/", handleAdmin(token), guard(token))
	e.FileFS("/css/layout.css/", "layout.css", css.CssFiles)
	e.GET("/", handleHome(token), optionalGuard(token))
}

func handleLogin(token auth.LoginToken, store *storage.StorageService, auth auth.AuthMethod) echo.HandlerFunc {
	return func(c echo.Context) error {
		t := c.QueryParam("token")
		if t != "" {
			info, err := token.Validate(t)
			if err != nil {
				return fmt.Errorf("handleLogin [token.Validate] [%w]", err)
			}
			return logUserIn(c, store, &info.UserInfo, token)
		}
		_, ok := userFromRequest(c)
		if ok {
			return c.Redirect(http.StatusTemporaryRedirect, "/")
		}
		return c.Redirect(http.StatusTemporaryRedirect, auth.RedirectUrl())
	}
}

func handleLogout(token auth.LoginToken) echo.HandlerFunc {
	return func(c echo.Context) error {
		_, ok := userFromRequest(c)
		if ok {
			cookie, _ := c.Cookie(cookieName)
			cookie.MaxAge = -1
			cookie.Path = "/"
			c.SetCookie(cookie)
		}
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}
}

func handleExpired() echo.HandlerFunc {
	return func(c echo.Context) error {
		data := templates.TemplateData(nil, "Expired")
		return c.Render(http.StatusOK, "expired.html", data)
	}
}

func handleOAuth2IdpResponse(auth auth.AuthMethod, store *storage.StorageService, token auth.LoginToken) echo.HandlerFunc {
	return func(c echo.Context) error {
		info, err := auth.HandleCallback(c.Request())
		if err != nil {
			return fmt.Errorf("handleOAuth2IdpResponse [auth.HandleCallback] [%w]", err)
		}
		return logUserIn(c, store, info, token)
	}
}

func handleAdmin(token auth.LoginToken) echo.HandlerFunc {
	return func(c echo.Context) error {
		user, _ := userFromRequest(c)
		if !user.Superuser {
			return ErrOnlySuperAllowed
		}
		return c.Render(http.StatusOK, "admin.html", templates.TemplateData(user, "Admin"))
	}
}

func handleHome(token auth.LoginToken) echo.HandlerFunc {
	return func(c echo.Context) error {
		user, _ := userFromRequest(c)
		data := templates.TemplateData(user, "Home")
		return c.Render(http.StatusOK, "index.html", data)
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

func logUserIn(c echo.Context, store storage.Storage, info *auth.UserInfo, token auth.LoginToken) error {
	ctx := c.Request().Context()
	usr, err := store.GetUserByUsername(ctx, info.Username)
	if err == storage.ErrUserNotFound {
		usr.Email = info.Email
		usr.Username = info.Username
		usr.Superuser = info.Superuser
		usr, err = store.PutUser(ctx, usr, false)
		c.Logger().Printf("created user [%s]\n", usr.Username)
	}
	if err != nil {
		return fmt.Errorf("logUserIn [store.GetUserByUsername] [%w]", err)
	}
	info.Id = usr.Id
	info.Superuser = usr.Superuser

	accessToken, err := token.SignToken(*info)
	if err != nil {
		return fmt.Errorf("logUserIn [token.SignToken] [%w]", err)
	}
	expiredTime := time.Now().Add(tokenExpirationTime)
	cookie := &http.Cookie{
		Name:     cookieName,
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expiredTime,
		MaxAge:   int((tokenExpirationTime) / time.Second),
	}
	c.SetCookie(cookie)
	return c.Redirect(http.StatusTemporaryRedirect, "/")
}

func hasPermission(ctx context.Context, store *storage.StorageService, accountId string, userId string, permissionType string, scope string, value string) error {
	has, err := store.HasPermission(ctx, storage.PermissionId{UserId: userId, AccountId: accountId, Type: permissionType, Scope: scope}, value)
	if err != nil {
		return err
	}
	if !has {
		return ErrNoPermissionInAccount
	}
	return nil
}
