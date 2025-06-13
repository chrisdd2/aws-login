package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"

	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func NewMemoryStorage(filename string) (storage.Storage, func(), error) {
	store := storage.NewMemoryStorage()

	f, err := os.Open(filename)
	if err != nil {
		log.Println(err)
	} else {
		if err := store.LoadFromReader(f); err != nil {
			return nil, nil, fmt.Errorf("store.LoadFromReader [%w]", err)
		}
	}
	defer f.Close()
	flushFunc := func(s *storage.MemoryStorage) {
		log.Printf("saving storage to [%s]\n", filename)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatalln(err)
		}
		if err := s.SaveToWriter(f); err != nil {
			f.Close()
			log.Fatalln(err)
		}
		f.Close()
		f, err = os.Open(filename)
		if err := s.LoadFromReader(f); err != nil {
			log.Fatalln(err)
		}
		defer f.Close()
	}
	store.SetFlush(flushFunc)
	exitSignal := make(chan os.Signal, 10)
	signal.Notify(exitSignal, os.Interrupt, os.Kill)
	go func() {
		<-exitSignal
		store.Flush()
		os.Exit(1)
	}()
	return store, store.Flush, nil
}

type storageCtx struct {
	store    storage.Storage
	saveFunc func()
}

func prepareStorage(cfg *AppConfig) (storageCtx, error) {
	switch cfg.StorageType {
	case StorageTypeSql:
		log.Printf("Using SQL storage backend: %s", cfg.DatabaseUrl)
		store, err := storage.NewSQLStorage(cfg.DatabaseUrl)
		return storageCtx{store: store, saveFunc: func() {}}, err
	case StorageTypeMemory:
		log.Printf("Using in-memory storage backend (MemoryStorage)")
		store, saveStorage, err := NewMemoryStorage(cfg.StorageFile)
		return storageCtx{store: store, saveFunc: saveStorage}, err
	default:
		return storageCtx{}, fmt.Errorf("unknown storage type %s", cfg.StorageType)
	}
}

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

func main() {
	appCfg := AppConfig{}
	appCfg.SetEnvironmentVariablePrefix("APP_")
	must(appCfg.LoadDefaults())
	must(appCfg.LoadFromEnv())

	appCfg.debugPrint()

	storageCtx := must2(prepareStorage(&appCfg))
	defer storageCtx.saveFunc()

	// allow different aws config for the aws user used for permissions in the other accounts
	stsClient := must2(withEnvContext(appCfg.PrefixEnv("ASSUMER_"), func() (*sts.Client, error) {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, err
		}
		// sts client will be used for most access we require
		return sts.NewFromConfig(cfg), nil
	}))

	// check which user it is
	stsResp := must2(stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{}))
	log.Printf("using assumer [%s]\n", aws.PrincipalFromSts(*stsResp.Arn))

	token := auth.LoginToken{
		Key: []byte(appCfg.SignKey),
	}

	authMethod := &auth.GithubAuth{
		ClientSecret: appCfg.GithubClientSecret,
		ClientId:     appCfg.GithubClientId,
	}

	e := echo.New()
	e.Renderer = &templates.EchoRenderer{}

	// Middleware
	e.Pre(middleware.AddTrailingSlash())
	if appCfg.DevelopmentMode {
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
			Format:           "${time_custom} method=${method}, uri=${uri}, status=${status}\n",
			CustomTimeFormat: "2006/01/02 15:04:05",
		}))
	} else {
		e.Use(middleware.Logger())
	}
	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())

	e.HTTPErrorHandler = func(err error, c echo.Context) {
		switch v := err.(type) {
		case *echo.HTTPError:
			c.JSON(http.StatusInternalServerError, map[string]string{
				"error": fmt.Sprint(v.Message),
			})
		default:
			c.JSON(http.StatusInternalServerError, map[string]string{
				"error": v.Error(),
			})
		}
	}

	webui.Router(e, authMethod, &storage.StorageService{Storage: storageCtx.store}, token, stsClient)

	log.Printf("listening [http://%s]\n", appCfg.ListenAddr)

	if appCfg.GenerateRootToken {
		accessToken, err := token.SignToken(auth.UserInfo{
			Username:  "root",
			Email:     "root@root",
			Superuser: true,
		})
		if err != nil {
			e.StdLogger.Fatalf("failed to generate root token [%s]\n", err)
		}
		e.StdLogger.Printf("ROOT access token: %s\n", accessToken)
		e.StdLogger.Printf("login with http://%s/login?token=%s\n", appCfg.ListenAddr, accessToken)
	}

	if err := e.Start(appCfg.ListenAddr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("failed to start server", "error", err)
	}
}
