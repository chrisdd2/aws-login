package webui

import (
	"context"
	"net/http"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
)

const cookieName = "AwsLoginAuthCookie"
const tokenExpirationTime = time.Hour * 8

func Router(e *echo.Echo, auth auth.AuthMethod, store storage.Storage, token auth.LoginToken, stsCl aws.StsClient) {

	accountsRouter(e,token, store, stsCl)
	e.GET("/login/", func(ctx echo.Context) error {
		_, ok := userFromRequest(ctx)
		if ok {
			return ctx.Redirect(http.StatusTemporaryRedirect, "/")
		}
		return ctx.Redirect(http.StatusTemporaryRedirect, auth.RedirectUrl())
	})
	e.GET("/logout/", func(ctx echo.Context) error {
		_, ok := userFromRequest(ctx)
		if ok {
			c, _ := ctx.Cookie(cookieName)
			c.MaxAge = -1
			c.Path = "/"
			ctx.SetCookie(c)
		}
		return ctx.Redirect(http.StatusTemporaryRedirect, "/")
	})
	e.GET("/expired/", func(ctx echo.Context) error {
		data := templates.TemplateData(nil, "Expired")
		return ctx.Render(http.StatusOK, "expired.html", data)
	})
	e.GET("/oauth2/idpresponse/", func(c echo.Context) error {
		ctx := c.Request().Context()
		info, err := auth.HandleCallback(c.Request())
		if err != nil {
			return err
		}
		usr, err := store.GetUserByUsername(ctx, info.Username)
		if err == storage.ErrUserNotFound {
			usr.Email = info.Email
			usr.Username = info.Username
			usr, err = store.PutUser(ctx, usr, false)
			c.Logger().Printf("created user [%s]\n", usr.Username)
		}
		if err != nil {
			return err
		}
		info.Id = usr.Id
		info.Superuser = usr.Superuser

		access_token, err := token.SignToken(*info)
		if err != nil {
			return err
		}
		expiredTime := time.Now().Add(tokenExpirationTime)
		cookie := http.Cookie{
			Name:     cookieName,
			Value:    access_token,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteLaxMode,
			Expires:  expiredTime,
			MaxAge:   int((tokenExpirationTime) / time.Second),
		}
		c.SetCookie(&cookie)
		return c.Redirect(http.StatusTemporaryRedirect, "/")
	})

	e.GET("/", func(ctx echo.Context) error {
		user, _ := userFromRequest(ctx)
		data := templates.TemplateData(user, "Home")
		return ctx.Render(http.StatusOK, "index.html", data)
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

func assumeOpRole(ctx context.Context, stsCl aws.StsClient, acc storage.Account) (awsSdk.Config, error) {
	arn := acc.ArnForRole(aws.OpsRole)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(stscreds.NewAssumeRoleProvider(stsCl, arn, func(aro *stscreds.AssumeRoleOptions) {
		aro.RoleSessionName = "aws-login"
		aro.Duration = time.Minute
	})))
	if err != nil {
		return awsSdk.Config{}, err
	}
	return cfg, nil
}
