package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"log/slog"
	"net/http"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
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
	awsContext := must2(appconfig.WithEnvContext(appCfg.PrefixEnv("ASSUMER_"), func() (awsSdk.Config, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return cfg, err
		}
		return cfg, nil
	}))

	stsClient := sts.NewFromConfig(awsContext)
	awsApi := must2(aws.NewAwsApi(ctx, stsClient))
	// check which user it is
	_, arn := must3(awsApi.WhoAmI(ctx))

	slog.Info("aws", "principal", arn)

	storageSvc := services.NewStaticStore(&appCfg, awsContext)
	must(storageSvc.Reload(ctx))
	slog.Info("found", "accounts", len(storageSvc.Accounts), "users", len(storageSvc.Users), "roles", len(storageSvc.Roles))

	tokenSvc := services.NewToken(storageSvc, []byte(appCfg.SignKey))
	roleSvc := services.NewRoleService(storageSvc, awsApi)
	accSvc := services.NewAccountService(storageSvc, awsApi)
	idps := []services.AuthService{}
	if appCfg.GithubEnabled {
		idps = append(idps, &services.GithubService{ClientSecret: appCfg.GithubClientSecret, ClientId: appCfg.GithubClientId, AuthResponsePath: "/oauth2/github/idpresponse"})
		slog.Info("enabled", "auth", "github")
	}
	if appCfg.OpenIdEnabled {
		idps = append(idps, must2(services.NewOpenId(ctx, appCfg.OpenIdProviderUrl, appCfg.OpenIdRedirectUrl, appCfg.OpenIdClientId, appCfg.OpenIdClientSecret)))
		slog.Info("enabled", "auth", "keycloak")
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

	r.Mount("/", webui.Router(tokenSvc, idps, roleSvc, accSvc, storageSvc, appCfg.AdminUsername, appCfg.AdminPassword, appCfg.RootUrl))

	logger.Info("listening", "address", appCfg.ListenAddr, "url", fmt.Sprintf("http:/%s", appCfg.ListenAddr))
	must(http.ListenAndServe(appCfg.ListenAddr, r))

}
