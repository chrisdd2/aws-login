package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"log/slog"
	"net/http"
	"net/url"

	awsSdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/api"
	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/aws"
	"github.com/chrisdd2/aws-login/internal/services"
	"github.com/chrisdd2/aws-login/internal/services/account"
	"github.com/chrisdd2/aws-login/internal/services/storage"
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

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	appCfg := appconfig.AppConfig{}

	flag.StringVar(&appCfg.ConfigFile, "config-file", "app.conf.yml", "config file path")
	flag.Parse()
	slog.Info("info", "version", version, "commit", commit, "date", date)

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
	cache, err := NewFileCache("aws-login")
	if err != nil {
		slog.Debug("cache", "cannot_create_dir", "aws-login", "err", err.Error())
	}

	ctx, cancel := shutdownContext(context.Background())
	defer cancel(nil)

	// AWS setup
	// allow different aws config for the aws user used for permissions in the other accounts
	assumerConfig, arn := must3(awsContext(ctx, "ASSUMER_"))
	slog.Info("aws", "principal", arn, "user", "assumer")
	s3Config, arn := must3(awsContext(ctx, "S3_"))
	slog.Info("aws", "principal", arn, "user", "s3")

	// storage
	var storageSvc storage.Storage
	switch appCfg.Storage.Type {
	case appconfig.StorageTypeFile:
		s := must2(storage.NewStaticStore(ctx, &appCfg, s3Config))
		must(s.Reload(ctx))
		must(s.Validate(ctx))
		slog.Info("found", "accounts", len(s.Accounts), "users", len(s.Users), "roles", len(s.Roles))
		storageSvc = s
	case appconfig.StorageTypePostgres:
		storageSvc = must2(storage.NewPostgresStore(ctx, &appCfg))
	}

	// sign key
	var signKey []byte = []byte(appCfg.Auth.SignKey)
	// make sure we got a sign key
	if len(signKey) == 0 {
		buf, _ := cache.Read("signkey") // Cache read errors are non-fatal; we'll regenerate
		if len(buf) == 0 {
			buf = make([]byte, 120)
			rand.Read(buf)
			buf = base64.StdEncoding.AppendEncode(nil, buf)
			_ = cache.Write("signkey", buf) // Write errors are logged but non-fatal
		}
		signKey = must2(base64.StdEncoding.AppendDecode(nil, buf))
		slog.Info("signkey", "size", len(buf))
	}

	// event store
	eventer, ok := storageSvc.(storage.Eventer)
	if !ok {
		eventer = storage.ConsoleEventer{}
	}

	// simple services
	tokenSvc := services.NewToken(storageSvc, signKey)
	awsApi := must2(aws.NewAwsApi(ctx, sts.NewFromConfig(assumerConfig)))
	roleSvc := services.NewRoleService(storageSvc, awsApi, eventer)
	accSvc := account.NewAccountService(storageSvc, awsApi, eventer)

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
		idps = append(idps, must2(services.NewOpenId(ctx, "keycloak", appCfg.Auth.Keycloak, appCfg.IsProduction())))
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
		idps = append(idps, must2(services.NewOpenId(ctx, "google", appCfg.Auth.Google, appCfg.IsProduction())))
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

	r.Mount("/", webui.Router(cancel, tokenSvc, idps, roleSvc, accSvc, storageSvc, appCfg, eventer))

	metricsRouter := chi.NewRouter()
	metricsRouter.Handle("/metrics", metrics.Handler())

	metricsSrv := gracefullServer{
		Name: "http_metrics",
		Server: http.Server{
			Handler: metricsRouter,
			Addr:    appCfg.MetrisAddr,
		},
	}
	go func() {
		metricsSrv.Listen(cancel)
	}()

	srv := gracefullServer{
		Name: "http",
		Server: http.Server{
			Handler: r,
			Addr:    appCfg.ListenAddr,
		},
	}

	go func() {
		srv.Listen(cancel)
	}()

	// wait for exit
	<-ctx.Done()

	if cause := context.Cause(ctx); cause != nil {
		slog.Info("shutting_down", "cause", cause.Error())
	}

	ctx, timeoutCancel := context.WithTimeout(context.Background(), time.Second*5)
	defer timeoutCancel()
	srv.Shutdown(ctx)
	metricsSrv.Shutdown(ctx)
}

func shutdownContext(parent context.Context) (context.Context, context.CancelCauseFunc) {
	ctx, cancel := context.WithCancelCause(parent)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		select {
		case <-ctx.Done():
			break
		case v := <-sigChan:
			cancel(fmt.Errorf("%s signal", v))
			break
		}
		signal.Stop(sigChan)
	}()
	return ctx, cancel
}

type gracefullServer struct {
	Name   string
	Server http.Server
}

func (g *gracefullServer) Listen(cancel context.CancelCauseFunc) {
	slog.Info(g.Name, "address", g.Server.Addr, "url", fmt.Sprintf("http:/%s", g.Server.Addr))
	err := g.Server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Info("http", "error", err.Error())
		cancel(err)
	}
}
func (g *gracefullServer) Shutdown(ctx context.Context) {
	if err := g.Server.Shutdown(ctx); err != nil {
		slog.Info(g.Name, "shutdown_error", err.Error())
	}
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
	cache := &cache{}
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	cacheDir := filepath.Join(homeDir, ".cache", subDir)
	if err := os.MkdirAll(cacheDir, 0755); err != nil {
		return nil, err
	}
	cache.cacheDir = cacheDir
	return cache, nil
}

func (c *cache) Write(filename string, buf []byte) error {
	if c.cacheDir == "" {
		return nil
	}
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
	if c.cacheDir == "" {
		return []byte{}, nil
	}
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
