package main

import (
	"context"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/embed"
	"github.com/chrisdd2/aws-login/storage"
)

type captureStatusCodeWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *captureStatusCodeWriter) Write(data []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (w *captureStatusCodeWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func loadStorage(file string) (*storage.MemoryStorage, error) {
	f, err := os.Open(file)
	if err != nil {
		log.Println(err)
		return storage.NewMemoryStorage(), nil
	}
	defer f.Close()
	return storage.NewMemoryStorageFromJson(f)
}

func loggerWrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := captureStatusCodeWriter{ResponseWriter: w}
		handler.ServeHTTP(&writer, r)
		log.Printf("%s: %d %s %s\n", r.RemoteAddr, writer.statusCode, r.Method, r.URL.Path)
	})
}

func main() {
	filename := "store.json"

	store, err := loadStorage(filename)
	if err != nil {
		log.Fatalln(err)
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
	defer saveStorage()
	exitSignal := make(chan os.Signal, 10)
	signal.Notify(exitSignal, os.Interrupt, os.Kill)
	go func() {
		<-exitSignal
		saveStorage()
		os.Exit(1)
	}()

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalln(err)
	}

	apiRouter := NewApiRouter(store, &auth.GithubAuth{
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		ClientId:     os.Getenv("CLIENT_ID"),
	},
		auth.LoginToken{
			Key: []byte("hello"),
		}, sts.NewFromConfig(cfg),
	)
	assetsFS, err := fs.Sub(embed.AssetsFs, "assets")
	if err != nil {
		log.Fatalln(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", apiRouter))
	mux.Handle("/", http.FileServerFS(assetsFS))

	addr := envOrDefault("APP_LISTEN_ADDR", "0.0.0.0:8080")
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
