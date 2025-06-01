package webui

import (
	"errors"
	"fmt"
	"net/http"
	"slices"

	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
)

var ErrAccountDisabled = errors.New("account is disabled")
var ErrNoPermissionInAccount = errors.New("no permission in this account")
var ErrNoPermissionAction = errors.New("no permission to perform this action")
var ErrOnlySuperAllowed = errors.New("only superusers are allowed to perform this action")

func accountsRouter(e *echo.Echo, token auth.LoginToken, store storage.Storage, stsCl aws.StsClient) {
	g := e.Group("/accounts")
	g.Use(guard(token))
	g.GET("/", handleAccounts(store))
	g.POST("/:accountId/disable/", handleAccountEnableToggle(store, false))
	g.POST("/:accountId/enable/", handleAccountEnableToggle(store, true))
	g.GET("/:accountId/roles/", handleRoles(store))
	g.GET("/:accountId/credentials/", handleCredentialsLogin(store, stsCl))
	g.GET("/:accountId/console/", handleConsoleLogin(store, stsCl))
	g.GET("/:accountId/cloudformation/", func(c echo.Context) error {
		ctx := c.Request().Context()
		_, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}
		c.Response().Header().Set("Content-Type", "text/yaml")
		return aws.BootstrapTemplate(ctx, stsCl, c.Response())
	})
	g.GET("/:accountId/bootstrap/", func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		if !user.Superuser {
			return ErrOnlySuperAllowed
		}
		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}

		// assume ops role
		resp, _ := stsCl.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		selfArn := aws.PrincipalFromSts(*resp.Arn)
		cfg, err := assumeOpRole(ctx, stsCl, acc)
		if err != nil {
			return err
		}
		cfn := cloudformation.NewFromConfig(cfg)

		err = aws.DeployBaseStack(ctx, cfn, selfArn)
		if err != nil {
			return err
		}
		data := templates.TemplateData(user, "Accounts")
		data.Accounts = []storage.Account{acc}
		return c.Render(http.StatusOK, "account.html", data)
	})
	g.GET("/:accountId/", handleAccount(store))
}

func handleRoles(store storage.Storage) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)

		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}

		roles := []templates.Role{}
		if user.Superuser {
			roles = append(roles, templates.Role{
				Arn:       acc.ArnForRole(aws.DeveloperRole),
				Name:      aws.AwsRole(aws.DeveloperRole).String(),
				AccountId: acc.Id,
				CanGrant:  true,
				CanAssume: true,
			})
			roles = append(roles, templates.Role{
				Arn:       acc.ArnForRole(aws.ReadOnlyRole),
				Name:      aws.AwsRole(aws.ReadOnlyRole).String(),
				AccountId: acc.Id,
				CanGrant:  true,
				CanAssume: true,
			})
		} else {

			permissionMap := map[string]templates.Role{}

			// get all permissions for user
			listPerms, err := store.ListUserPermissions(ctx, user.Id, acc.Id, "", nil)
			if err != nil {
				return err
			}
			// it should be at least one perm
			if len(listPerms.UserPermissions) < 1 {
				return ErrNoPermissionInAccount
			}
			for _, perm := range listPerms.UserPermissions {
				for _, role := range perm.Value {
					rolePerm, ok := permissionMap[role]
					if !ok {
						permissionMap[role] = templates.Role{
							Arn:       acc.ArnForRole(role),
							Name:      aws.AwsRole(role).String(),
							AccountId: acc.Id,
							CanGrant:  perm.Scope == storage.UserPermissionAdmin,
							CanAssume: perm.Scope == storage.UserPermissionAssume,
						}
						continue
					}
					rolePerm.CanGrant = rolePerm.CanGrant || perm.Scope == storage.UserPermissionAdmin
					rolePerm.CanAssume = rolePerm.CanAssume || perm.Scope == storage.UserPermissionAssume
					permissionMap[role] = rolePerm
				}
			}
			for _, v := range permissionMap {
				roles = append(roles, v)
			}
		}
		data := templates.TemplateData(user, "Roles")
		data.Roles = roles
		return c.Render(http.StatusOK, "roles.html", data)
	}
}

func accountFromRequest(c echo.Context, store storage.Storage) (storage.Account, error) {
	accountId := c.Param("accountId")
	acc, err := store.GetAccountById(c.Request().Context(), accountId)
	if err != nil {
		return storage.Account{}, err
	}
	if !acc.Enabled {
		return storage.Account{}, ErrAccountDisabled
	}
	return acc, nil
}

func handleAccountEnableToggle(store storage.Storage, value bool) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		accountId := c.Param("accountId")
		acc, err := store.GetAccountById(c.Request().Context(), accountId)
		if err != nil {
			return err
		}
		res, err := store.ListUserPermissions(ctx, user.Id, acc.Id, storage.UserPermissionAdmin, nil)
		if err != nil {
			return err
		}
		if len(res.UserPermissions) < 1 {
			return ErrNoPermissionAction
		}
		acc.Enabled = value
		_, err = store.PutAccount(ctx, acc, false)
		if err != nil {
			return err
		}
		return c.Redirect(http.StatusFound, fmt.Sprintf("/accounts/%s/", acc.Id))
	}
}

func handleAccounts(store storage.Storage) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		page := c.QueryParam("page")
		var res storage.ListAccountResult
		var err error
		if user.Superuser {
			res, err = store.ListAccounts(ctx, pointerString(page))
		} else {
			res, err = store.ListAccountsForUser(ctx, user.Id, pointerString(page))
		}
		if err != nil {
			return err
		}
		data := templates.TemplateData(user, "Accounts")
		data.Accounts = res.Accounts
		data.StartToken = toString(res.StartToken)
		return c.Render(http.StatusOK, "accounts.html", data)
	}
}

func handleAccount(store storage.Storage) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)

		accountId := c.Param("accountId")
		acc, err := store.GetAccountById(ctx, accountId)
		if err != nil {
			return err
		}

		data := templates.TemplateData(user, "Accounts")
		data.Accounts = []storage.Account{acc}
		return c.Render(http.StatusOK, "account.html", data)
	}
}

func canAssume(c echo.Context, store storage.Storage, user *auth.UserInfo, roleName string) (acc storage.Account, err error) {
	ctx := c.Request().Context()
	acc, err = accountFromRequest(c, store)
	if err != nil {
		return
	}

	listPerms, err := store.ListUserPermissions(ctx, user.Id, acc.Id, storage.UserPermissionAssume, nil)
	if err != nil {
		return
	}
	// it should be only one perm
	if len(listPerms.UserPermissions) != 1 {
		err = ErrNoPermissionInAccount
		return
	}

	if !slices.Contains(listPerms.UserPermissions[0].Value, roleName) {
		err = ErrNoPermissionAction
		return
	}
	return
}

func handleConsoleLogin(store storage.Storage, stsCl aws.StsClient) echo.HandlerFunc {

	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		roleName := aws.AwsRole(c.QueryParam("roleName")).RealName()

		acc, err := canAssume(c, store, user, roleName)
		if err != nil {
			return err
		}

		arn := acc.ArnForRole(roleName)
		url, err := aws.GenerateSigninUrl(ctx, stsCl, arn, user.Username, "https://console.aws.amazon.com/console/home")
		if err != nil {
			return fmt.Errorf("unable to generate url [%w]", err)
		}
		return c.Redirect(http.StatusTemporaryRedirect, url)
	}
}

func handleCredentialsLogin(store storage.Storage, stsCl aws.StsClient) echo.HandlerFunc {
	return func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		roleName := aws.AwsRole(c.QueryParam("roleName")).RealName()

		acc, err := canAssume(c, store, user, roleName)
		if err != nil {
			return err
		}

		arn := acc.ArnForRole(roleName)
		resp, err := stsCl.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &arn, RoleSessionName: &user.Username})
		if err != nil {
			return fmt.Errorf("unable to assume role [%w]", err)
		}
		return c.String(http.StatusOK, fmt.Sprintf("export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\nexport AWS_SESSION_TOKEN=%s",
			*resp.Credentials.AccessKeyId,
			*resp.Credentials.SecretAccessKey,
			*resp.Credentials.SessionToken,
		))
	}
}
