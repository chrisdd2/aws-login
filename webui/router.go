package webui

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"slices"
	"time"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui/templates"
)

const cookieName = "AwsLoginAuthCookie"
const tokenExpirationTime = time.Hour * 8

type WebUi struct {
	http.ServeMux
	store storage.Storage
	idp   auth.AuthMethod
	token auth.LoginToken
	sts   aws.StsClient
}

func NewWebUi(token auth.LoginToken, store storage.Storage, idp auth.AuthMethod, stsCl aws.StsClient) *WebUi {
	ui := WebUi{store: store, idp: idp, token: token, sts: stsCl}
	guard := authGuard{token: token, idp: idp}

	ui.Handle("GET /accounts/{accountId}/roles", guard.guard(ui.handleRoles))
	ui.Handle("GET /accounts/{accountId}/console", guard.guard(ui.handleConsoleLogin))
	ui.Handle("GET /accounts/{accountId}/credentials", guard.guard(ui.handleCredentials))
	ui.Handle("GET /accounts/{accountId}/", guard.guard(ui.handleAccount))
	ui.Handle("POST /accounts/{accountId}/disable", guard.guard(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		accountId := r.PathValue("accountId")
		user, _ := userFromRequest(r)

		acc, err := ui.store.GetAccountById(ctx, accountId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		acc.Enabled = false
		_, err = store.PutAccount(ctx, acc, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := templates.TemplateData(user, "Accounts")
		data.Accounts = []storage.Account{acc}
		renderTemplate(w, "account.html", data)
	}))
	ui.Handle("POST /accounts/{accountId}/enable", guard.guard(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		accountId := r.PathValue("accountId")
		user, _ := userFromRequest(r)

		acc, err := ui.store.GetAccountById(ctx, accountId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		acc.Enabled = true
		_, err = store.PutAccount(ctx, acc, false)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		data := templates.TemplateData(user, "Accounts")
		data.Accounts = []storage.Account{acc}
		renderTemplate(w, "account.html", data)
	}))
	ui.Handle("GET /accounts/{accountId}/cloudformation", guard.guard(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		accountId := r.PathValue("accountId")

		acc, err := ui.store.GetAccountById(ctx, accountId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !acc.Enabled {
			http.Error(w, "Account is disabled", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/yaml")
		err = aws.BootstrapTemplate(ctx, ui.sts, w)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}))

	ui.Handle("POST /accounts/{accountId}/bootstrap", guard.guard(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		accountId := r.PathValue("accountId")

		user, _ := userFromRequest(r)
		if !user.Superuser {
			http.Error(w, "Only superusers can bootstrap accounts", http.StatusUnauthorized)
			return
		}

		acc, err := ui.store.GetAccountById(ctx, accountId)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if !acc.Enabled {
			http.Error(w, "Account is disabled", http.StatusBadRequest)
			return
		}
		// assume ops role
		resp, _ := stsCl.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
		selfArn := aws.PrincipalFromSts(*resp.Arn)
		cfg, err := assumeOpRole(ctx, stsCl, acc)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		cfn := cloudformation.NewFromConfig(cfg)

		err = aws.DeployBaseStack(ctx, cfn, selfArn)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data := templates.TemplateData(user, "Accounts")
		data.Accounts = []storage.Account{acc}
		renderTemplate(w, "account.html", data)
	}))
	ui.Handle("GET /accounts/", guard.guard(ui.handleAccounts))
	ui.Handle("GET /login/", guard.optional(ui.handleLogin))
	ui.Handle("GET /expired/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		renderTemplate(w, "expired.html", templates.TemplateData(nil, "Expired"))
	}))
	ui.Handle("GET /logout/", guard.optional(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := userFromRequest(r)
		if ok {
			c, _ := r.Cookie(cookieName)
			c.MaxAge = -1
			c.Path = "/"
			http.SetCookie(w, c)
		}
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
	})))
	ui.Handle("GET /oauth2/idpresponse/", http.HandlerFunc(ui.handleCallback))
	ui.Handle("GET /", guard.optional(handleIndex))
	return &ui
}
func (ui *WebUi) handleLogin(w http.ResponseWriter, r *http.Request) {
	_, ok := userFromRequest(r)
	if ok {
		// already logged
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}
	http.Redirect(w, r, ui.idp.RedirectUrl(), http.StatusTemporaryRedirect)
}

func (ui *WebUi) handleCallback(w http.ResponseWriter, r *http.Request) {
	info, err := ui.idp.HandleCallback(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	usr, err := ui.store.GetUserByUsername(r.Context(), info.Username)
	if err == storage.ErrUserNotFound {
		usr.Email = info.Email
		usr.Username = info.Username
		usr, err = ui.store.PutUser(r.Context(), usr, false)
		log.Printf("created user [%s]\n", usr.Username)
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	info.Id = usr.Id
	info.Superuser = usr.Superuser

	access_token, err := ui.token.SignToken(*info)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
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
	http.SetCookie(w, &cookie)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (ui *WebUi) handleAccounts(w http.ResponseWriter, r *http.Request) {
	user, _ := userFromRequest(r)
	page := r.URL.Query().Get("page")
	var res storage.ListAccountResult
	var err error
	if user.Superuser {
		res, err = ui.store.ListAccounts(r.Context(), pointerString(page))
	} else {
		res, err = ui.store.ListAccountsForUser(r.Context(), user.Id, pointerString(page))
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	data := templates.TemplateData(user, "Accounts")
	data.Accounts = res.Accounts
	data.StartToken = toString(res.StartToken)
	renderTemplate(w, "accounts.html", data)
}

func (ui *WebUi) handleAccount(w http.ResponseWriter, r *http.Request) {

	ctx := r.Context()
	accountId := r.PathValue("accountId")
	user, _ := userFromRequest(r)

	acc, err := ui.store.GetAccountById(ctx, accountId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := templates.TemplateData(user, "Accounts")
	data.Accounts = []storage.Account{acc}
	renderTemplate(w, "account.html", data)
}

func (ui *WebUi) handleConsoleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountId := r.PathValue("accountId")
	roleName := aws.AwsRole(r.URL.Query().Get("roleName")).RealName()
	user, _ := userFromRequest(r)

	acc, err := ui.store.GetAccountById(ctx, accountId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !acc.Enabled {
		http.Error(w, "Account is disabled", http.StatusBadRequest)
		return
	}

	listPerms, err := ui.store.ListUserPermissions(ctx, user.Id, accountId, storage.UserPermissionAssume, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// it should be only one perm
	if len(listPerms.UserPermissions) != 1 {
		http.Error(w, "no permission in this account", http.StatusUnauthorized)
		return
	}

	if !slices.Contains(listPerms.UserPermissions[0].Value, roleName) {
		http.Error(w, "cannot assume this role", http.StatusUnauthorized)
		return
	}

	arn := acc.ArnForRole(roleName)
	url, err := aws.GenerateSigninUrl(ctx, ui.sts, arn, user.Username, "https://console.aws.amazon.com/console/home")
	if err != nil {
		http.Error(w, "unable to generate url "+err.Error(), http.StatusInternalServerError)
		return
	}
	// redirect to url
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (ui *WebUi) handleCredentials(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountId := r.PathValue("accountId")
	roleName := aws.AwsRole(r.URL.Query().Get("roleName")).RealName()
	user, _ := userFromRequest(r)

	acc, err := ui.store.GetAccountById(ctx, accountId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !acc.Enabled {
		http.Error(w, "Account is disabled", http.StatusBadRequest)
		return
	}

	listPerms, err := ui.store.ListUserPermissions(ctx, user.Id, accountId, storage.UserPermissionAssume, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// it should be only one perm
	if len(listPerms.UserPermissions) != 1 {
		http.Error(w, "no permission in this account", http.StatusUnauthorized)
		return
	}

	if !slices.Contains(listPerms.UserPermissions[0].Value, roleName) {
		http.Error(w, "cannot assume this role", http.StatusUnauthorized)
		return
	}

	arn := acc.ArnForRole(roleName)
	resp, err := ui.sts.AssumeRole(ctx, &sts.AssumeRoleInput{RoleArn: &arn, RoleSessionName: &user.Username})
	if err != nil {
		http.Error(w, "unable to assume role "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Add("Content-Type", "text/plain")
	fmt.Fprintf(w, "export AWS_ACCESS_KEY_ID=%s\nexport AWS_SECRET_ACCESS_KEY=%s\nexport AWS_SESSION_TOKEN=%s",
		*resp.Credentials.AccessKeyId,
		*resp.Credentials.SecretAccessKey,
		*resp.Credentials.SessionToken,
	)
}

func (ui *WebUi) handleRoles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	accountId := r.PathValue("accountId")

	user, _ := userFromRequest(r)

	acc, err := ui.store.GetAccountById(ctx, accountId)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !acc.Enabled {
		http.Error(w, "Account is disabled", http.StatusBadRequest)
		return
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
		listPerms, err := ui.store.ListUserPermissions(ctx, user.Id, accountId, "", nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// it should be at least one perm
		if len(listPerms.UserPermissions) < 1 {
			http.Error(w, "no permission in this account", http.StatusOK)
			return
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
				rolePerm.CanGrant = perm.Scope == storage.UserPermissionAdmin
				rolePerm.CanAssume = perm.Scope == storage.UserPermissionAssume
				permissionMap[role] = rolePerm
			}
		}
		for _, v := range permissionMap {
			roles = append(roles, v)
		}
	}
	data := templates.TemplateData(user, "Roles")
	data.Logged = true
	data.Roles = roles
	renderTemplate(w, "roles.html", data)
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	user, _ := userFromRequest(r)
	data := templates.TemplateData(user, "Home")
	renderTemplate(w, "index.html", data)
}

func renderTemplate(w http.ResponseWriter, name string, data any) {
	err := templates.RenderPage(w, name, data)
	if err != nil {
		log.Println(err)
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

func assumeOpRole(ctx context.Context, stsCl aws.StsClient, acc storage.Account) (awsSdk.Config, error) {
	arn := acc.ArnForRole(aws.OpsRole)
	cfg, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(stscreds.NewAssumeRoleProvider(stsCl, arn, func(aro *stscreds.AssumeRoleOptions) {
		aro.RoleSessionName = "aws-login"
		aro.Duration = time.Hour * 12
	})))
	if err != nil {
		return awsSdk.Config{}, err
	}
	return cfg, nil
}
