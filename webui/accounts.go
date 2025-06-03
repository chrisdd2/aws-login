package webui

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
	"github.com/r3labs/sse/v2"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
)

var ErrAccountDisabled = errors.New("account is disabled")
var ErrNoPermissionInAccount = errors.New("no permission in this account")
var ErrNoPermissionAction = errors.New("no permission to perform this action")
var ErrOnlySuperAllowed = errors.New("only superusers are allowed to perform this action")
var ErrInvalidGrant = errors.New("invalid grant from")

var inProgressStatus []string = []string{
	string(types.StackStatusCreateInProgress),
	string(types.StackStatusRollbackInProgress),
	string(types.StackStatusUpdateInProgress),
	string(types.StackStatusUpdateCompleteCleanupInProgress),
	string(types.StackStatusUpdateRollbackInProgress),
	string(types.StackStatusUpdateRollbackCompleteCleanupInProgress),
	string(types.StackStatusReviewInProgress),
	string(types.StackStatusDeleteInProgress),
}

func accountsRouter(e *echo.Echo, token auth.LoginToken, store *storage.StorageService, stsCl aws.StsClient) {
	g := e.Group("/accounts")
	g.Use(guard(token))
	g.GET("/", handleAccounts(store))
	g.GET("/create/", func(c echo.Context) error {
		user, _ := userFromRequest(c)
		if !user.Superuser {
			return ErrOnlySuperAllowed
		}
		return c.Render(http.StatusOK, "account-create.html", templates.TemplateData(user, "Create Account"))
	})
	g.POST("/create/", func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		if !user.Superuser {
			return ErrOnlySuperAllowed
		}
		type CreateAccount struct {
			FriendlyName string `form:"friendly_name"`
			AwsAccountId string `form:"aws_account_id"`
			Enabled      string `form:"enabled"`
			Tags         string `form:"tags"`
		}
		createAccount := CreateAccount{}
		if err := c.Bind(&createAccount); err != nil {
			return err
		}
		awsAccountId, err := strconv.ParseInt(createAccount.AwsAccountId, 10, 64)
		if err != nil {
			// this should never happen because of the above regex
			return storage.ErrInvalidAccountDetails
		}
		acc, err := store.CreateAccount(ctx, storage.Account{
			AwsAccountId: int(awsAccountId),
			FriendlyName: createAccount.FriendlyName,
			Enabled:      createAccount.Enabled == "on",
			Tags:         parseTags(createAccount.Tags),
		})
		if err != nil {
			return err
		}

		return redirectoAccount(c, acc.Id)
	})
	g.POST("/:accountId/delete/", func(c echo.Context) error {
		ctx := c.Request().Context()
		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}
		_, err = store.PutAccount(ctx, acc, true)
		if err != nil {
			return err
		}
		return c.Redirect(http.StatusFound, "/accounts/")
	})
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
	g.GET("/:accountId/bootstrap/status/", func(c echo.Context) error {

		ctx := c.Request().Context()
		stackId := c.QueryParam("stackId")
		user, _ := userFromRequest(c)
		if !user.Superuser {
			return ErrOnlySuperAllowed
		}

		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}
		// assume ops role
		cfg, err := assumeOpRole(ctx, stsCl, acc)
		if err != nil {
			return err
		}
		cfn := cloudformation.NewFromConfig(cfg)

		srv := sse.New()
		srv.CreateStream("bootstrap")

		go func() {
			ticker := time.NewTicker(time.Second * 3)
			timeoutCtx, cancel := context.WithTimeout(ctx, time.Minute*15)
			defer srv.Close()
			defer cancel()
			defer ticker.Stop()
			for {
				select {
				case <-c.Request().Context().Done():
					log.Printf("SSE client disconnected, ip: %v", c.RealIP())
					return
				case <-ticker.C:
					resp, err := cfn.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{StackName: &stackId})
					if err != nil {
						srv.Publish("bootstrap", &sse.Event{
							Data: []byte(fmt.Sprintf("error describing stack %s\n", err)),
						})
						log.Println(err)
						return
					}
					status := string(resp.Stacks[0].StackStatus)
					srv.Publish("bootstrap", &sse.Event{
						Data: []byte(fmt.Sprintf("%s: %s", time.Now().UTC(), status)),
					})
					if !slices.Contains(inProgressStatus, status) {
						return
					}
				case <-timeoutCtx.Done():
					srv.Publish("bootstrap", &sse.Event{
						Data: []byte("timed out"),
					})
					return
				}
			}
		}()
		srv.ServeHTTP(c.Response().Writer, c.Request())
		return nil
	})
	g.POST("/:accountId/bootstrap/destroy/", func(c echo.Context) error {
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

		stackId, err := aws.DestroyBaseStack(ctx, cfn, selfArn)
		if err != nil {
			return err
		}
		// render template with status support
		data := templates.TemplateData(user, "Bootstrap status")
		data.StackId = url.QueryEscape(stackId)
		data.Accounts = []storage.Account{acc}
		return c.Render(http.StatusOK, "bootstrap-status.html", data)
	})
	g.POST("/:accountId/bootstrap/", func(c echo.Context) error {
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

		stackId, err := aws.DeployBaseStack(ctx, cfn, selfArn)
		if err != nil {
			return err
		}
		// render template with status support
		data := templates.TemplateData(user, "Bootstrap status")
		data.StackId = url.QueryEscape(stackId)
		data.Accounts = []storage.Account{acc}
		return c.Render(http.StatusOK, "bootstrap-status.html", data)
	})

	g.GET("/:accountId/revoke/", func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)

		roleName := aws.AwsRole(c.QueryParam("roleName")).RealName()

		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}
		perms, err := store.ListPermissions(ctx, "", acc.Id, storage.RolePermission, roleName, pointerString(c.QueryParam("page")))
		if err != nil {
			return err
		}
		userIds := []string{}
		for _, perm := range perms.Permissions {
			if perm.UserId == user.Id {
				// skip self
				continue
			}
			userIds = append(userIds, perm.UserId)
		}
		users, err := store.BatchGetUserById(ctx, userIds...)
		if err != nil {
			return err
		}

		data := templates.TemplateData(user, "Revoke Role permission")
		data.Roles = []templates.Role{templates.Role{Arn: acc.ArnForRole(roleName), Name: roleName}}
		data.Accounts = []storage.Account{acc}
		data.StartToken = toString(perms.StartToken)

		// this is somewhat slow, but we are doing page wise so, its fine
		for _, user := range users {
			for _, perm := range perms.Permissions {
				if perm.UserId == user.Id {
					data.UserPermissions = append(data.UserPermissions, struct {
						Permission storage.Permission
						User       storage.User
					}{
						Permission: perm,
						User:       user,
					})
					break
				}
			}
		}

		return c.Render(http.StatusOK, "revoke.html", data)
	})

	g.POST("/:accountId/revoke/", func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)

		type RevokeAction struct {
			RoleName string `form:"roleName"`
			UserId   string `form:"userId"`
			Value    string `form:"value"`
		}

		action := RevokeAction{}
		if err := c.Bind(&action); err != nil {
			return err
		}
		roleName := aws.AwsRole(action.RoleName).RealName()

		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}

		// check if current user has access to grant
		if !user.Superuser {
			err := hasPermission(ctx, store, acc.Id, user.Id, storage.RolePermission, roleName, storage.RolePermissionGrant)
			if err != nil {
				return err
			}
		}
		// get permission
		perms, err := store.ListPermissions(ctx, action.UserId, acc.Id, storage.RolePermission, roleName, nil)
		if err != nil {
			return err
		}
		if len(perms.Permissions) == 0 {
			// nothing to do i guess
			return c.Redirect(http.StatusFound, fmt.Sprintf("/accounts/%s/revoke/", acc.Id))
		}
		perm := perms.Permissions[0]
		perm.Value = slices.DeleteFunc(perm.Value, func(a string) bool {
			return a == action.Value
		})
		deletePerm := len(perm.Value) == 0
		if err := store.PutRolePermission(ctx, perm, deletePerm); err != nil {
			return err
		}
		return c.Redirect(http.StatusFound, fmt.Sprintf("/accounts/%s/revoke/", acc.Id))
	})
	g.GET("/:accountId/grant/", func(c echo.Context) error {
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		roleName := aws.AwsRole(c.QueryParam("roleName")).RealName()
		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}
		if !user.Superuser {
			err := hasPermission(ctx, store, acc.Id, user.Id, storage.RolePermission, roleName, storage.RolePermissionGrant)
			if err != nil {
				return err
			}
		}
		users, _ := store.ListUsers(ctx, "", nil)
		data := templates.TemplateData(user, "Grant Role permission")
		data.Roles = []templates.Role{templates.Role{Arn: acc.ArnForRole(roleName), Name: roleName}}
		data.Users = users.Users
		data.Accounts = []storage.Account{acc}
		return c.Render(http.StatusOK, "grant.html", data)
	})

	g.POST("/:accountId/grant/", func(c echo.Context) error {
		type GrantForm struct {
			Username   string `form:"username"`
			Permission string `form:"permission"`
		}
		ctx := c.Request().Context()
		user, _ := userFromRequest(c)
		roleName := aws.AwsRole(c.QueryParam("roleName")).RealName()

		acc, err := accountFromRequest(c, store)
		if err != nil {
			return err
		}

		// check form
		form := GrantForm{}
		if err := c.Bind(&form); err != nil {
			return err
		}
		log.Println(form)
		if form.Username == "" {
			return ErrInvalidGrant
		}
		if form.Permission != storage.RolePermissionAssume && form.Permission != storage.RolePermissionGrant && form.Permission != "BOTH" {
			return ErrInvalidGrant
		}

		permToAdd := []string{form.Permission}
		if form.Permission == "BOTH" {
			permToAdd = []string{storage.RolePermissionAssume, storage.RolePermissionGrant}
		}

		// check if current user has access to grant
		if !user.Superuser {
			err := hasPermission(ctx, store, acc.Id, user.Id, storage.RolePermission, roleName, storage.RolePermissionGrant)
			if err != nil {
				return err
			}
		}

		// check if the request user exists
		usr, err := store.GetUserByUsername(ctx, form.Username)
		if err != nil {
			return err
		}
		// check existing permission if any
		perms, err := store.ListPermissions(ctx, usr.Id, acc.Id, storage.RolePermission, roleName, nil)
		perm := storage.Permission{
			PermissionId: storage.PermissionId{UserId: usr.Id, AccountId: acc.Id, Type: storage.RolePermission, Scope: roleName},
		}
		if len(perms.Permissions) > 0 {
			perm = perms.Permissions[0]
		}
		added := false
		for _, v := range permToAdd {
			if !slices.Contains(perm.Value, v) {
				perm.Value = append(perm.Value, v)
				added = true
			}
		}
		// add if something changed
		if added {
			if err = store.PutRolePermission(ctx, perm, false); err != nil {
				return err
			}
		}
		return c.Redirect(http.StatusFound, fmt.Sprintf("/accounts/%s/roles/", acc.Id))
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
			for _, role := range acc.Roles() {
				roles = append(roles, templates.Role{
					Arn:       acc.ArnForRole(role),
					Name:      aws.AwsRole(role).String(),
					AccountId: acc.Id,
					CanGrant:  true,
					CanAssume: true,
				})

			}
		} else {
			// get all permissions for user
			listPerms, err := store.ListPermissions(ctx, user.Id, acc.Id, storage.RolePermission, "", nil)
			if err != nil {
				return err
			}
			// it should be at least one perm
			if len(listPerms.Permissions) < 1 {
				return ErrNoPermissionInAccount
			}
			for _, role := range listPerms.Permissions {
				roles = append(roles, templates.Role{
					Arn:       acc.ArnForRole(role.Scope),
					Name:      aws.AwsRole(role.Scope).String(),
					AccountId: acc.Id,
					CanGrant:  slices.Contains(role.Value, storage.RolePermissionGrant),
					CanAssume: slices.Contains(role.Value, storage.RolePermissionAssume),
				})
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
		if !user.Superuser {
			// check if admin permission is present
			perm, err := store.ListPermissions(ctx, user.Id, acc.Id, storage.AccountAdminPermission, storage.AccountAdminScopeAccount, nil)
			if err != nil {
				return err
			}
			if len(perm.Permissions) != 1 {
				return ErrNoPermissionAction
			}
			if !slices.Contains(perm.Permissions[0].Value, storage.AccountAdminPermissionEnabled) {
				return ErrNoPermissionAction
			}
		}
		acc.Enabled = value
		_, err = store.PutAccount(ctx, acc, false)
		if err != nil {
			return err
		}
		return redirectoAccount(c, acc.Id)
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

	if user.Superuser {
		return
	}

	listPerms, err := store.ListPermissions(ctx, user.Id, acc.Id, storage.RolePermission, roleName, nil)
	if err != nil {
		return
	}
	// it should be only one perm
	if len(listPerms.Permissions) != 1 {
		err = ErrNoPermissionInAccount
		return
	}

	if !slices.Contains(listPerms.Permissions[0].Value, storage.RolePermissionAssume) {
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

func assumeOpRole(ctx context.Context, stsCl aws.StsClient, acc storage.Account) (awsSdk.Config, error) {
	arn := acc.ArnForRole(aws.OpsRole)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(stscreds.NewAssumeRoleProvider(stsCl, arn, func(aro *stscreds.AssumeRoleOptions) {
		aro.RoleSessionName = "aws-login"
		aro.Duration = time.Minute * 15 // minimum
	})))
	if err != nil {
		return awsSdk.Config{}, err
	}
	return cfg, nil
}

func redirectoAccount(c echo.Context, accountId string) error {
	return c.Redirect(http.StatusFound, fmt.Sprintf("/accounts/%s/", accountId))
}

func parseTags(tagString string) map[string]string {
	tags := map[string]string{}
	lines := strings.Split(tagString, "\n")
	for _, line := range lines {
		key, value, _ := strings.Cut(line, "=")
		value = strings.TrimSpace(value)
		if value == "" {
			value = "-"
		}
		tags[strings.TrimSpace(key)] = value
	}
	return tags
}
