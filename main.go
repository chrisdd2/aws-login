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
	saveStorage := func() {
		log.Printf("saving storage to [%s]\n", filename)
		f, err := os.Create(filename)
		if err != nil {
			log.Fatalln(err)
		}
		err = storage.SaveMemoryStorageFromJson(store, f)
		if err != nil {
			log.Fatalln(err)
		}
	}
	exitSignal := make(chan os.Signal, 10)
	signal.Notify(exitSignal, os.Interrupt, os.Kill)
	go func() {
		<-exitSignal
		saveStorage()
		os.Exit(1)
	}()
	return store, saveStorage, nil
}

func main() {
	addr := envOrDefault("APP_LISTEN_ADDR", "0.0.0.0:8080")
	filename := envOrDefault("APP_STORE_FILE", "store.json")

	store, saveStorage, err := initStorage(filename)
	if err != nil {
		log.Fatalln(err)
	}
	defer saveStorage()

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalln(err)
	}

	token := auth.LoginToken{
		Key: []byte("hello"),
	}

	authMethod := &auth.GithubAuth{
		ClientSecret: envOrDie("CLIENT_SECRET"),
		ClientId:     envOrDie("CLIENT_ID"),
	}
	// for range 10 {
	// 	acc, _ := store.PutAccount(context.Background(), storage.Account{
	// 		AwsAccountId: rand.Int(),
	// 		FriendlyName: fmt.Sprintf("mine-%d", rand.Int()),
	// 		Enabled:      true,
	// 	}, false)
	// 	store.PutUserPermission(context.Background(), storage.UserPermission{
	// 		UserPermissionId: storage.UserPermissionId{
	// 			UserId:    "42f669d4074b49ef9d9ed72191c1a216",
	// 			AccountId: acc.Id,
	// 			Scope:     storage.UserPermissionAssume,
	// 		},
	// 		Value: []string{aws.DeveloperRole, aws.ReadOnlyRole},
	// 	}, false)
	// }

	e := echo.New()
	e.Renderer = &templates.EchoRenderer{}

	// Middleware
	e.Pre(middleware.AddTrailingSlash())
	e.Use(middleware.Logger())
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
	webui.Router(e, authMethod, store, token, stsCient)

	log.Printf("listening [http://%s]\n", addr)
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
