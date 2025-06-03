package webui

import (
	"net/http"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
	"fmt"
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
	g.GET("/", handleUsersList(store))
	g.POST("/:userId/delete/", handleUserDelete(store))
	g.POST("/:userId/demote/", handleUserDemote(store))
	g.POST("/:userId/promote/", handleUserPromote(store))
}

func handleUsersList(store storage.Storage) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		page := c.QueryParam("page")
		res, err := store.ListUsers(ctx, "", pointerString(page))
		if err != nil {
			return fmt.Errorf("handleUsersList [store.ListUsers] [%w]", err)
		}
		data := templates.TemplateData(user, "Users")
		data.Users = res.Users
		data.StartToken = toString(res.StartToken)
		return c.Render(http.StatusOK, "users.html", data)
	}
}

func handleUserDelete(store storage.Storage) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		userId := c.Param("userId")
		_, err := store.PutUser(ctx, storage.User{Id: userId}, true)
		if err != nil {
			return fmt.Errorf("handleUserDelete [store.PutUser] [%w]", err)
		}
		return c.Redirect(http.StatusFound, "/users")
	}
}

func handleUserDemote(store storage.Storage) echo.HandlerFunc {
	return handleUserSuperuserSet(store, false)
}

func handleUserPromote(store storage.Storage) echo.HandlerFunc {
	return handleUserSuperuserSet(store, true)
}

func handleUserSuperuserSet(store storage.Storage, v bool) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		userId := c.Param("userId")
		usr, err := store.GetUserById(ctx, userId)
		if err != nil {
			return fmt.Errorf("handleUserSuperuserSet [store.GetUserById] [%w]", err)
		}
		usr.Superuser = v
		_, err = store.PutUser(ctx, usr, false)
		if err != nil {
			return fmt.Errorf("handleUserSuperuserSet [store.PutUser] [%w]", err)
		}
		return c.Redirect(http.StatusFound, "/users")
	}
}
