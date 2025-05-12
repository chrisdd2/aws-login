package main

import (
	"context"
	"io/fs"
	"net/http"
	"os"
	"os/signal"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/embed"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func example() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	redirectUrl := "https://console.aws.amazon.com/console/home"

	for role, err := range findRolesIterator(context.Background(), iam.NewFromConfig(cfg), "assumeable-role") {
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		log.Info().Msg(role)
		url, err := generateSigninUrl(context.Background(), sts.NewFromConfig(cfg), role, "mysession", redirectUrl)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		log.Info().Msg(url)
	}
}

type captureStatusCodeWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *captureStatusCodeWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func loadStorage(file string) (*storage.MemoryStorage, error) {
	f, err := os.Open(file)
	if err != nil {
		log.Info().Err(err).Send()
		return &storage.MemoryStorage{}, nil
	}
	defer f.Close()
	return storage.NewMemoryStorageFromJson(f)
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	filename := "store.json"

	store, err := loadStorage(filename)
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	saveStorage := func() {
		log.Info().Str("filename", filename).Msg("saving storage")
		f, err := os.Create(filename)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
		err = storage.SaveMemoryStorageFromJson(store, f)
		if err != nil {
			log.Fatal().Err(err).Send()
		}
	}
	defer saveStorage()
	exitSignal := make(chan os.Signal, 10)
	signal.Notify(exitSignal, os.Interrupt, os.Kill)
	go func() {
		<-exitSignal
		saveStorage()
		os.Exit(1)
	}()

	assets, err := fs.Sub(embed.AssetsFs, "assets")
	if err != nil {
		log.Fatal().Err(err).Send()
	}
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServerFS(assets))
	if err := http.ListenAndServe(":8080", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := captureStatusCodeWriter{ResponseWriter: w}
		mux.ServeHTTP(&writer, r)
		log.Info().Str("method", r.Method).Str("path", r.URL.Path).Str("from", r.RemoteAddr).Int("status-code", writer.statusCode).Send()
	})); err != nil {
		log.Fatal().Err(err).Send()
	}
}
