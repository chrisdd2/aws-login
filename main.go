package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"log/slog"
	"net/http"
	"net/url"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
func ternary[T any](c bool, a T, b T) T {
	if c {
		return a
	}
	return b
}

func main() {
	cache := must2(NewFileCache("aws-login"))
	appCfg := appconfig.AppConfig{}
	appCfg.SetEnvironmentVariablePrefix("app")
	must(appCfg.LoadDefaults())
	must(appCfg.LoadFromEnv())

	f, err := os.Open(appCfg.ConfigFile)
	if err == nil {
		must(appCfg.LoadFromYaml(f))
		f.Close()
	}

	logLvl := ternary(appCfg.DevelopmentMode, slog.LevelInfo, slog.LevelDebug)
	logger := ternary(appCfg.DevelopmentMode,
		slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLvl})),
		slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLvl})),
	)
	slog.SetDefault(logger)

	if appCfg.DevelopmentMode {
		appCfg.DebugPrint()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

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

	var signKey []byte = []byte(appCfg.Auth.SignKey)
	// make sure we got a sign key
	if len(signKey) == 0 {
		buf, _ := cache.Read("signkey")
		if len(buf) == 0 {
			buf = make([]byte, 120)
			rand.Read(buf)
			buf = base64.StdEncoding.AppendEncode(nil, buf)
			cache.Write("signkey", buf)
		}
		signKey = must2(base64.StdEncoding.AppendDecode(nil, buf))
		slog.Info("signkey", "size", len(buf))
	}

	var eventer services.Eventer
	if strings.HasPrefix(appCfg.EventsFile, "s3://") {
		s3Url := must2(url.Parse(appCfg.EventsFile))
		bucket, key := s3Url.Hostname(), strings.TrimPrefix(s3Url.Path, "/")
		s3Eventer := must2(services.NewS3Eventer(s3.NewFromConfig(s3Config), bucket, key))
		go s3Eventer.CommitLoop(ctx, time.Minute, 100, time.Minute*10)
		eventer = s3Eventer
		slog.Info("enabled", "eventer", "s3")
	} else {
		fileEventer := must2(services.NewFileEventer(appCfg.EventsFile))

		defer fileEventer.Close()
		eventer = fileEventer
		slog.Info("enabled", "eventer", "file")
	}
	tokenSvc := services.NewToken(storageSvc, signKey)
	roleSvc := services.NewRoleService(storageSvc, awsApi, eventer)
	accSvc := services.NewAccountService(storageSvc, awsApi, eventer)

	idps := []services.AuthService{}
	if appCfg.Auth.Github.Enabled() {
		u := must2(url.Parse(appCfg.Auth.Github.RedirectUrl))
		idps = append(idps, &services.GithubService{
			ClientSecret:     appCfg.Auth.Github.ClientSecret,
			ClientId:         appCfg.Auth.Github.ClientId,
			AuthResponsePath: u.Path,
		})
		slog.Info("enabled", "auth", "github")
	}
	if appCfg.Auth.Keycloak.Enabled() {
		idps = append(idps, must2(services.NewOpenId(ctx, "keycloak", appCfg.Auth.Keycloak)))
		slog.Info("enabled", "auth", "keycloak")
	}
	if appCfg.Auth.Google.Enabled() {
		validations := []services.OpenIdClaimsValidation{}
		if len(appCfg.Auth.GoogleWorkspaces) > 0 {
			validations = append(validations, func(claims services.OpenIdClaims) error {
				if !slices.Contains(appCfg.Auth.GoogleWorkspaces, claims.HD) {
					return fmt.Errorf("%s not in allowed workspaces", claims.Email)
				}
				return nil
			})
		}
		idps = append(idps, must2(services.NewOpenId(ctx, "google", appCfg.Auth.Google)))
		slog.Info("enabled", "auth", "google")
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
	r.Mount("/", webui.Router(tokenSvc, idps, roleSvc, accSvc, storageSvc, appCfg, eventer))

	metricsRouter := chi.NewRouter()
	metricsRouter.Handle("/metrics", metrics.Handler())
	go func() {
		slog.Info("metrics", "address", appCfg.MetrisAddr)
		if err := http.ListenAndServe(appCfg.MetrisAddr, metricsRouter); err != nil {
			slog.Error("metrics", "err", err)
		}
	}()

	slog.Info("http", "address", appCfg.ListenAddr, "url", fmt.Sprintf("http:/%s", appCfg.ListenAddr))
	if appCfg.Tls.ListenAddr != "" {
		go func() {
			slog.Info("https", "address", appCfg.Tls.ListenAddr, "url", fmt.Sprintf("https:/%s", appCfg.Tls.ListenAddr))
			must(http.ListenAndServeTLS(appCfg.Tls.ListenAddr, appCfg.Tls.CertFile, appCfg.Tls.KeyFile, r))
		}()
	}
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

type cache struct {
	cacheDir string
}

func NewFileCache(subDir string) (*cache, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cacheDir := filepath.Join(homeDir, ".cache", subDir)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}
	return &cache{cacheDir}, nil
}

func (c *cache) Write(filename string, buf []byte) error {
	filename = filepath.Join(c.cacheDir, filename)
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	f.Write(buf)
	f.Close()
	return nil
}
func (c *cache) Read(filename string) ([]byte, error) {
	filename = filepath.Join(c.cacheDir, filename)
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	buf, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	f.Close()
	return buf, nil
}
