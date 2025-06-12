package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"

	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
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

func main() {
	addr := envOrDefault("APP_LISTEN_ADDR", "0.0.0.0:8080")
	filename := envOrDefault("APP_STORE_FILE", "store.json")
	signKey := envOrDie("APP_SIGN_KEY")
	generateAdminToken := os.Getenv("APP_GENERATE_TOKEN") != ""
	dsn := os.Getenv("APP_DATABASE_URL") // Example: postgres://postgres:postgres@db:5432/postgres?sslmode=disable
	dynamoTable := os.Getenv("APP_DYNAMODB_TABLE")

	// Choose storage backend
	var (
		store       storage.Storage
		saveStorage func()
		err         error
	)
	if dynamoTable != "" {
		log.Printf("Using DynamoDB storage backend: %s", dynamoTable)

		// allow different aws config for dynamo db, i.e transform any APP_DYNAMO_AWS_* variables into AWS_* variables
		saveStorage = withEnvContext("APP_DYNAMODB_", func() func() {
			cfg, err := config.LoadDefaultConfig(context.Background())
			if err != nil {
				log.Fatalln(err)
			}
			dynamoClient := dynamodb.NewFromConfig(cfg)

			store, err = storage.NewDynamoDBStorage(dynamoClient, dynamoTable)
			if err != nil {
				log.Fatalln(err)
			}
			if err := store.(*storage.DynamoDBStorage).EnsureSchema(context.Background()); err != nil {
				log.Fatalln(err)
			}
			return func() {}
		})
	} else if dsn != "" {
		log.Printf("Using SQL storage backend: %s", dsn)
		store, err = storage.NewSQLStorage(dsn)
		saveStorage = func() {} // no-op
	} else {
		log.Printf("Using in-memory storage backend (MemoryStorage)")
		store, saveStorage, err = NewMemoryStorage(filename)
	}
	if err != nil {
		log.Fatalln(err)
	}

	defer saveStorage()

	// allow different aws config for the aws user used for permissions in the other accounts
	stsClient := withEnvContext("APP_ASSUMER_", func() *sts.Client {
		cfg, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			log.Fatalln(err)
		}
		// sts client will be used for most access we require
		return sts.NewFromConfig(cfg)
	})

	// check which user it is
	stsResp, err := stsClient.GetCallerIdentity(context.Background(), &sts.GetCallerIdentityInput{})
	if err != nil {
		log.Fatalln(err)
	}
	log.Printf("using assumer [%s]\n", aws.PrincipalFromSts(*stsResp.Arn))

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

	webui.Router(e, authMethod, &storage.StorageService{Storage: store}, token, stsClient)

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

func getEnvironmentVariablesWithPrefix(prefix string) map[string]string {
	res := map[string]string{}
	for _, env := range os.Environ() {
		key, value, _ := strings.Cut(env, "=")
		if strings.HasPrefix(key, prefix) {
			res[strings.TrimPrefix(key, prefix)] = value
		}
	}
	return res
}

func withEnvContext[T any](prefix string, f func() T) T {
	restore := environmentContext(getEnvironmentVariablesWithPrefix(prefix))
	t := f()
	restore()
	return t
}

func environmentContext(envVars map[string]string) (restoreFunc func()) {
	restore := map[string]string{}
	unset := []string{}
	for k, v := range envVars {
		restoreVal, exists := os.LookupEnv(k)
		if exists {
			restore[k] = restoreVal
		} else {
			unset = append(unset, k)
		}
		os.Setenv(k, v)
	}
	return func() {
		for k, v := range restore {
			os.Setenv(k, v)
		}
		for _, k := range unset {
			os.Unsetenv(k)
		}
	}
}
