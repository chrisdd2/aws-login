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
	"github.com/chrisdd2/aws-login/api"
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
	logLvl := slog.LevelInfo
	if appCfg.DevelopmentMode {
		logLvl = slog.LevelDebug
	}
	if appCfg.DevelopmentMode {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLvl}))
	} else {
		logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLvl}))
	}
	slog.SetDefault(logger)

	appCfg.DebugPrint()

	ctx := context.Background()

	// AWS setup
	// allow different aws config for the aws user used for permissions in the other accounts
	assumerConfig, arn := must3(awsContext(ctx, "ASSUMER_"))
	slog.Info("aws", "principal", arn, "user", "assumer")
	s3Config, arn := must3(awsContext(ctx, "S3_"))
	slog.Info("aws", "principal", arn, "user", "s3")

	storageSvc := services.NewStaticStore(&appCfg, s3Config)
	must(storageSvc.Reload(ctx))
	slog.Info("found", "accounts", len(storageSvc.Accounts), "users", len(storageSvc.Users), "roles", len(storageSvc.Roles))
	must(storageSvc.Validate())

	awsApi := must2(aws.NewAwsApi(ctx, sts.NewFromConfig(assumerConfig)))
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

	r.Mount("/api", api.V1Api(accSvc, idps, roleSvc, tokenSvc))
	r.Mount("/", webui.Router(tokenSvc, idps, roleSvc, accSvc, storageSvc, appCfg))

	metricsRouter := chi.NewRouter()
	metricsRouter.Handle("/metrics", metrics.Handler())
	go func() {
		slog.Info("metrics", "address", appCfg.MetrisAddr)
		if err := http.ListenAndServe(appCfg.MetrisAddr, metricsRouter); err != nil {
			slog.Error("metrics", "err", err)
		}
	}()

	slog.Info("http", "address", appCfg.ListenAddr, "url", fmt.Sprintf("http:/%s", appCfg.ListenAddr))
	must(http.ListenAndServe(appCfg.ListenAddr, r))

}

func awsContext(ctx context.Context, environmentPrefix string) (awsConfig awsSdk.Config, arn string, err error) {
	cfg, err := appconfig.WithEnvContext(environmentPrefix, func() (awsSdk.Config, error) {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return cfg, err
		}
		return cfg, nil
	})
	if err != nil {
		return awsConfig, "", err
	}
	stsCl := sts.NewFromConfig(cfg)
	resp, err := stsCl.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return awsConfig, "", err
	}
	return cfg, awsSdk.ToString(resp.Arn), nil
}
