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
	"github.com/labstack/echo/v4"
)

const cookieName = "AwsLoginAuthCookie"
const tokenExpirationTime = time.Hour * 8

func Router(e *echo.Echo, auth auth.AuthMethod, store storage.Storage, token auth.LoginToken, stsCl aws.StsClient) {

	accountsRouter(e, token, store, stsCl)
	usersRouter(e, store, token)
	e.GET("/login/", func(c echo.Context) error {
		t := c.QueryParam("token")
		// login with a token i guess?
		if t != "" {
			info, err := token.Validate(t)
			if err != nil {
				return err
			}
			return logUserIn(c, store, &info.UserInfo, token)
		}
		_, ok := userFromRequest(c)
		if ok {
			return c.Redirect(http.StatusTemporaryRedirect, "/")
		}
		return c.Redirect(http.StatusTemporaryRedirect, auth.RedirectUrl())
	})
	e.GET("/logout/", func(c echo.Context) error {
		_, ok := userFromRequest(c)
		if ok {
			cookie, _ := c.Cookie(cookieName)
			log.Println(cookie)
			cookie.MaxAge = -1
			cookie.Path = "/"
			c.SetCookie(cookie)
		}
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	}, guard(token))
	e.GET("/expired/", func(c echo.Context) error {
		data := templates.TemplateData(nil, "Expired")
		return c.Render(http.StatusOK, "expired.html", data)
	})
	e.GET("/oauth2/idpresponse/", func(c echo.Context) error {
		info, err := auth.HandleCallback(c.Request())
		if err != nil {
			return err
		}
		return logUserIn(c, store, info, token)
	})
	e.GET("/admin/", func(c echo.Context) error {
		user, _ := userFromRequest(c)
		if !user.Superuser {
			return ErrOnlySuperAllowed
		}
		return c.Render(http.StatusOK, "admin.html", templates.TemplateData(user, "Admin"))
	}, guard(token))

	e.GET("/", func(c echo.Context) error {
		user, _ := userFromRequest(c)
		data := templates.TemplateData(user, "Home")
		return c.Render(http.StatusOK, "index.html", data)
	}, optionalGuard(token))
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
		return err
	}
	info.Id = usr.Id
	info.Superuser = usr.Superuser

	accessToken, err := token.SignToken(*info)
	if err != nil {
		return err
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

func hasPermission(ctx context.Context, store storage.Storage, accountId string, userId string, permissionType string, scope string, value string) error {
	res, err := store.ListPermissions(ctx, userId, accountId, permissionType, scope, nil)
	if err != nil {
		return err
	}
	if len(res.Permissions) != 1 {
		return ErrNoPermissionAction
	}
	if slices.Contains(res.Permissions[0].Value, value) {
		return nil
	}
	return ErrNoPermissionAction
}
