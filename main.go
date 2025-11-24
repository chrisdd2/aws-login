package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
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
	storage := must2(storage.NewJsonBackend(appCfg.StorageFile))

	exitSignal := make(chan os.Signal, 10)
	signal.Notify(exitSignal, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-exitSignal
		err := storage.Close()
		if err != nil {
			logger.Error("error saving storage [%s]", err)
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

	log.Printf("using assumer [%s]\n", arn)

	// Authentication
	token := auth.LoginToken{
		Key: []byte(appCfg.SignKey),
	}

	authMethod := &auth.GithubAuth{
		ClientSecret: appCfg.GithubClientSecret,
		ClientId:     appCfg.GithubClientId,
	}

	if appCfg.GenerateRootToken {
		accessToken := must2(token.SignToken(auth.UserInfo{
			Username:  "root",
			Email:     "root@root",
			Superuser: true,
		}, auth.DefaultTokenExpiration))
		logger.Info("ROOT access token: %s\n", accessToken)
		logger.Info("login with http://%s/login?token=%s\n", appCfg.ListenAddr, accessToken)
	}

	// Http server
	router := http.NewServeMux()
	router.Handle("/api", nil)
	router.Handle("/", nil)
	handler := addTrailingSlash(router)

	log.Printf("listening [http://%s]\n", appCfg.ListenAddr)
	must(http.ListenAndServe(appCfg.ListenAddr, handler))

}

func addTrailingSlash(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/") {
			r.URL = r.URL.JoinPath("/")
		}
		h.ServeHTTP(w, r)
	})
}
