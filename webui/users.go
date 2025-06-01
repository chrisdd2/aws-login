package webui

import (
	"net/http"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
)

func usersRouter(e *echo.Echo, store storage.Storage, token auth.LoginToken) {
	g := e.Group("/users")
	g.Use(guard(token))
	g.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			user, _ := userFromRequest(c)
			if user.Superuser {
				return next(c)
			}
			return ErrOnlySuperAllowed
		}
	})
	redirectToMain := func(c echo.Context) error {
		return c.Redirect(http.StatusFound, "/users")
	}

	g.GET("/", func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		page := c.QueryParam("page")
		res, err := store.ListUsers(ctx, "", pointerString(page))
		if err != nil {
			return err
		}
		data := templates.TemplateData(user, "Users")
		data.Users = res.Users
		data.StartToken = toString(res.StartToken)
		return c.Render(http.StatusOK, "users.html", data)
	})
	g.POST("/:userId/delete/", func(c echo.Context) error {
		ctx := c.Request().Context()
		userId := c.Param("userId")
		_, err := store.PutUser(ctx, storage.User{Id: userId}, true)
		if err != nil {
			return err
		}
		return redirectToMain(c)
	})
	superUserSet := func(v bool) echo.HandlerFunc {
		return func(c echo.Context) error {
			ctx := c.Request().Context()
			userId := c.Param("userId")
			usr, err := store.GetUserById(ctx, userId)
			if err != nil {
				return err
			}
			usr.Superuser = v
			_, err = store.PutUser(ctx, usr, false)
			if err != nil {
				return err
			}
			return redirectToMain(c)
		}
	}
	g.POST("/:userId/demote/", superUserSet(false))
	g.POST("/:userId/promote/", superUserSet(true))

}
