package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/chrisdd2/aws-login/webui"
)

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

	apiRouter := NewApiRouter(store, &auth.GithubAuth{
		ClientSecret: envOrDie("CLIENT_SECRET"),
		ClientId:     envOrDie("CLIENT_ID"),
	},
		auth.LoginToken{
			Key: []byte("hello"),
		}, sts.NewFromConfig(cfg),
	)

	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", apiRouter))
	mux.Handle("/", &webui.WebUi{})
	log.Printf("listening [http://%s]\n", addr)
	if err := http.ListenAndServe(addr, loggerWrap(mux)); err != nil {
		log.Fatalln(err)
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
