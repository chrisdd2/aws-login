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
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui"
	"github.com/chrisdd2/aws-login/webui/templates"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func loadStorage(file string) (*storage.MemoryStorage, error) {
	f, err := os.Open(file)
	if err != nil {
		log.Println(err)
		return storage.NewMemoryStorage(), nil
	}
	defer f.Close()
	return storage.NewMemoryStorageFromJson(f)
}

func initStorage(filename string) (storage.Storage, func(), error) {
	store, err := loadStorage(filename)
	if err != nil {
		return nil, nil, fmt.Errorf("loadStorage [%w]", err)
	}
	flushFunc := func(s *storage.MemoryStorage) {
		log.Printf("saving storage to [%s]\n", filename)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatalln(err)
		}
		err = storage.SaveMemoryStorageFromJson(s, f)
		if err != nil {
			log.Fatalln(err)
		}
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

func main() {
	addr := envOrDefault("APP_LISTEN_ADDR", "0.0.0.0:8080")
	filename := envOrDefault("APP_STORE_FILE", "store.json")
	signKey := envOrDie("APP_SIGN_KEY")
	generateAdminToken := os.Getenv("APP_GENERATE_TOKEN") != ""
	dsn := os.Getenv("APP_DATABASE_URL") // Example: postgres://postgres:postgres@db:5432/postgres?sslmode=disable
	dynamoTable := os.Getenv("APP_DYNAMODB_TABLE")

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalln(err)
	}

	// Choose storage backend
	var (
		store       storage.Storage
		saveStorage func()
	)
	if dynamoTable != "" {
		log.Printf("Using DynamoDB storage backend: %s", dynamoTable)
		dynamoClient := dynamodb.NewFromConfig(cfg)
		store, err = storage.NewDynamoDBStorage(dynamoClient, dynamoTable)
		if err != nil {
			log.Fatalln(err)
		}
		if err := store.(*storage.DynamoDBStorage).EnsureSchema(context.Background()); err != nil {
			log.Fatalln(err)
		}
		saveStorage = func() {} // no-op
	} else if dsn != "" {
		log.Printf("Using SQL storage backend: %s", dsn)
		store, err = storage.NewSQLStorage(dsn)
		saveStorage = func() {} // no-op
	} else {
		log.Printf("Using in-memory storage backend (MemoryStorage)")
		store, saveStorage, err = initStorage(filename)
	}
	if err != nil {
		log.Fatalln(err)
	}
	defer saveStorage()

	token := auth.LoginToken{
		Key: []byte(signKey),
	}

	authMethod := &auth.GithubAuth{
		ClientSecret: envOrDie("APP_CLIENT_SECRET"),
		ClientId:     envOrDie("APP_CLIENT_ID"),
	}

	e := echo.New()
	e.Renderer = &templates.EchoRenderer{}

	// Middleware
	e.Pre(middleware.AddTrailingSlash())
	if envOrDefault("APP_DEVELOPMENT_MODE", "") != "" {
		e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
			Format: "method=${method}, uri=${uri}, status=${status}\n",
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

	stsCient := sts.NewFromConfig(cfg)
	webui.Router(e, authMethod, &storage.StorageService{Storage: store}, token, stsCient)

	log.Printf("listening [http://%s]\n", addr)

	if generateAdminToken {
		accessToken, err := token.SignToken(auth.UserInfo{
			Username:  "root",
			Email:     "root@root",
			Superuser: true,
		})
		if err != nil {
			e.StdLogger.Fatalf("failed to generate root token [%s]\n", err)
		}
		e.StdLogger.Printf("ROOT access token: %s\n", accessToken)
		e.StdLogger.Printf("login with http://%s/login?token=%s\n", addr, accessToken)
	}

	if err := e.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("failed to start server", "error", err)
	}
}

func envOrDefault(name string, def string) string {
	v := os.Getenv(name)
	if v != "" {
		return v
	}
	return def
}

func envOrDie(name string) string {
	v := os.Getenv(name)
	if v == "" {
		panic(fmt.Sprintf("missing %s environment variable", name))
	}
	return v
}
