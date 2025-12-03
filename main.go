package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/services"
	sg "github.com/chrisdd2/aws-login/storage"
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
	appCfg := AppConfig{}
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

	appCfg.debugPrint()

	ctx := context.Background()

	// storage setup
	assert(appCfg.StorageType == "memory", "only memory storage support atm")
	storage := must2(sg.NewJsonBackend(appCfg.StorageFile))

	exitSignal := make(chan os.Signal, 10)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-exitSignal
		err := storage.Close()
		if err != nil {
			logger.Error("error saving storage", "error", err)
		}
		os.Exit(1)
	}()

	// AWS setup
	// allow different aws config for the aws user used for permissions in the other accounts
	stsClient := must2(withEnvContext(appCfg.PrefixEnv("ASSUMER_"), func() (*sts.Client, error) {
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

	// Authentication
	token := services.NewToken(storage, []byte(appCfg.SignKey))

	if appCfg.GenerateRootToken {
		accessToken := must2(token.Create(ctx, &services.UserInfo{
			Username:  "root",
			Email:     "root@root",
			Superuser: true,
		}))
		logger.Info("Generated token", "access token", accessToken)
		logger.Info("login with", "url", fmt.Sprintf("http://%s/login?token=%s", appCfg.ListenAddr, accessToken))
	}

	// _ = &auth.GithubAuth{
	// 	ClientSecret: appCfg.GithubClientSecret,
	// 	ClientId:     appCfg.GithubClientId,
	// }
	idp := must2(services.NewOpenId(ctx, "http://localhost:8080/realms/grafana", "http://localhost:8090/oauth2/idpresponse", "awslogin", "x8CQn6u68os9NbJOHX2nQpkMdIxcfx40"))
	log.Println(idp.RedirectUrl())

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

	// api := api.V1Api()
	// r.Mount("/api", api)

	r.Mount("/", webui.Router(token, idp))

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
