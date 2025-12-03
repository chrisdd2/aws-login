package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/services"
	"github.com/chrisdd2/aws-login/webui"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/metrics"
)

func must(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}
func must2[T any](a T, err error) T {
	if err != nil {
		log.Fatalln(err)
	}
	return a
}
func must3[T any, Y any](a T, b Y, err error) (T, Y) {
	if err != nil {
		log.Fatalln(err)
	}
	return a, b
}
func assert(cond bool, msg string) {
	if !cond {
		log.Fatalln(msg)
	}
}

func main() {
	appCfg := appconfig.AppConfig{}
	appCfg.SetEnvironmentVariablePrefix("APP_")
	must(appCfg.LoadDefaults())
	must(appCfg.LoadFromEnv())

	var logger *slog.Logger
	if appCfg.DevelopmentMode {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))
	} else {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{}))
	}
	slog.SetDefault(logger)

	appCfg.DebugPrint()

	ctx := context.Background()

	// AWS setup
	// allow different aws config for the aws user used for permissions in the other accounts
	stsClient := must2(appconfig.WithEnvContext(appCfg.PrefixEnv("ASSUMER_"), func() (*sts.Client, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, err
		}
		// sts client will be used for most access we require
		return sts.NewFromConfig(cfg), nil
	}))

	awsApi := must2(aws.NewAwsApi(ctx, stsClient))
	// check which user it is
	_, arn := must3(awsApi.WhoAmI(ctx))

	logger.Info("using", "assumer", arn)

	storageSvc := &services.Store{}
	if appCfg.ConfigDirectory != "" {
		entries := must2(os.ReadDir(appCfg.ConfigDirectory))
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := filepath.Join(appCfg.ConfigDirectory, entry.Name())
			o := services.Store{}
			log.Printf("loading file [%s]\n", name)
			f := must2(os.Open(name))
			if strings.HasSuffix(name, ".yml") {
				must(o.LoadYaml(f))
			} else if strings.HasSuffix(name, "json") {
				must(o.LoadJson(f))
			}
			f.Close()
			storageSvc = storageSvc.Merge(&o)
		}
	}
	// storageSvc.Accounts = append(storageSvc.Accounts, appconfig.Account{
	// 	Name:         "main",
	// 	AwsAccountId: 992885815868,
	// 	Enabled:      true,
	// })
	// storageSvc.Users = append(storageSvc.Users, appconfig.User{
	// 	Name:      "chrisdd2",
	// 	Email:     "chris.damianidis2@gmail.com",
	// 	Superuser: true,
	// 	Roles: []appconfig.RoleAttachment{
	// 		{RoleName: "developer-role", AccountName: "main", Permissions: []string{"console"}},
	// 		{RoleName: "readonly-role", AccountName: "main", Permissions: []string{"credential", "console"}},
	// 	},
	// })
	// storageSvc.Roles = append(storageSvc.Roles, appconfig.Role{
	// 	Name:               "developer-role",
	// 	MaxSessionDuration: time.Hour * 8,
	// 	Enabled:            true,
	// 	AssociatedAccounts: []string{"main"},
	// 	ManagedPolicies:    []string{"arn:aws:iam::aws:policy/AdministratorAccess"},
	// })
	// storageSvc.Roles = append(storageSvc.Roles, appconfig.Role{
	// 	Name:               "readonly-role",
	// 	MaxSessionDuration: time.Hour * 8,
	// 	Enabled:            true,
	// 	AssociatedAccounts: []string{"main"},
	// 	ManagedPolicies:    []string{"arn:aws:iam::aws:policy/ReadOnlyAccess"},
	// })
	// f := must2(os.Create(".config/test.yml"))
	// must(yaml.NewEncoder(f).Encode(&storageSvc))
	// f.Close()
	// f = must2(os.Open(".config/test.yml"))
	// must(yaml.NewDecoder(f).Decode(&storageSvc))
	// f.Close()

	tokenSvc := services.NewToken(storageSvc, []byte(appCfg.SignKey))
	roleSvc := services.NewRoleService(storageSvc, awsApi)
	accSvc := services.NewAccountService(storageSvc, awsApi)
	idps := []services.AuthService{}
	if appCfg.GithubEnabled {
		idps = append(idps, &services.GithubService{ClientSecret: appCfg.GithubClientSecret, ClientId: appCfg.GithubClientId, AuthResponsePath: "/oauth2/github/idpresponse"})
		log.Println("[github] login enabled")
	}
	if appCfg.OpenIdEnabled {
		idps = append(idps, must2(services.NewOpenId(ctx, appCfg.OpenIdProviderUrl, appCfg.OpenIdRedirectUrl, appCfg.OpenIdClientId, appCfg.OpenIdClientSecret)))
		log.Println("[keycloak] login enabled")
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Logger)
	r.Use(metrics.Collector(metrics.CollectorOpts{
		Host:  false,
		Proto: true,
		Skip: func(r *http.Request) bool {
			return r.Method != "OPTIONS"
		},
	}))

	r.Handle("/metrics", metrics.Handler())

	r.Mount("/", webui.Router(tokenSvc, idps, roleSvc, accSvc, appCfg.AdminUsername, appCfg.AdminPassword))

	// api := api.V1Api()
	// r.Mount("/api", api)
	// key, _ := rsa.GenerateKey(rand.Reader, 2048)
	// jwks := goidc.JSONWebKeySet{
	// 	Keys: []goidc.JSONWebKey{{
	// 		KeyID:     "key_id",
	// 		Key:       key,
	// 		Algorithm: "RS256",
	// 	}},
	// }
	// policy := goidc.NewPolicy("main", func(r *http.Request, c *goidc.Client, as *goidc.AuthnSession) bool {
	// 	return true
	// }, func(w http.ResponseWriter, r *http.Request, as *goidc.AuthnSession) (goidc.AuthnStatus, error) {
	// 	ctx := r.Context()
	// 	authorization, found := strings.CutPrefix("Bearer ", r.Header.Get("Authorization"))
	// 	if !found {
	// 		return goidc.StatusFailure, errors.New("missing authorization token")
	// 	}
	// 	info, err := token.Validate(ctx, authorization)
	// 	if err != nil {
	// 		return goidc.StatusFailure, err
	// 	}
	// 	_, err = storage.GetUser(ctx, info.Id)
	// 	if err != nil {
	// 		return goidc.StatusFailure, err
	// 	}
	// 	client, err := storage.GetOAuthClient(ctx, as.ClientID)
	// 	if err != nil {
	// 		return goidc.StatusFailure, err
	// 	}
	// 	roles := []string{}
	// 	for _, acc := range client.Accounts {
	// 		nextToken := (*string)(nil)
	// 		for {
	// 			seq, token, err := storage.ListRolePermissions(ctx,acc,info.Id,nextToken)
	// 			if err !=nil {
	// 				return goidc.StatusFailure,nil
	// 			}
	// 			for role := range seq{
	// 			}
	// 		}
	// 	}
	// 	as.AdditionalUserInfoClaims
	// 	as.AdditionalUserInfoClaims
	// })
	// op, _ := provider.New(
	// 	goidc.ProfileOpenID,
	// 	"http://localhost:8090",
	// 	func(_ context.Context) (goidc.JSONWebKeySet, error) {
	// 		return jwks, nil
	// 	},
	// 	provider.WithPolicies(policy))
	// r.Mount("/oidc", op.Handler())

	logger.Info("listening", "address", appCfg.ListenAddr, "url", fmt.Sprintf("http:/%s", appCfg.ListenAddr))
	must(http.ListenAndServe(appCfg.ListenAddr, r))

}
