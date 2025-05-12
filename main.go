package main

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/embed"
	"github.com/chrisdd2/aws-login/storage"
)

func example() {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		log.Fatalln(err)
	}
	redirectUrl := "https://console.aws.amazon.com/console/home"

	for role, err := range findRolesIterator(context.Background(), iam.NewFromConfig(cfg), "assumeable-role") {
		if err != nil {
			log.Fatalln(err)
		}
		url, err := generateSigninUrl(context.Background(), sts.NewFromConfig(cfg), role, "mysession", redirectUrl)
		if err != nil {
			log.Fatalln(err)
		}
		log.Println(url)
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
		log.Println(err)
		return &storage.MemoryStorage{}, nil
	}
	defer f.Close()
	return storage.NewMemoryStorageFromJson(f)
}

func loggerWrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := captureStatusCodeWriter{ResponseWriter: w}
		handler.ServeHTTP(&writer, r)
		log.Printf("%s: %d %s %s\n", r.RemoteAddr, r.Method, r.URL.Path, writer.statusCode)
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

	assets, err := fs.Sub(embed.AssetsFs, "assets")
	if err != nil {
		log.Fatalln(err)
	}
	token := auth.LoginToken{
		Key: []byte("hello"),
	}
	auth := auth.GithubAuth{
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		ClientId:     os.Getenv("CLIENT_ID"),
	}
	apiRouter := NewApiRouter(store)
	apiRouter.HandleFunc("/auth/github", func(w http.ResponseWriter, r *http.Request) {
		info, err := auth.HandleCallback(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// enc := json.NewEncoder(w)
		// enc.SetIndent("", "  ")
		// err = enc.Encode(info)
		jwtToken, err := token.SignToken(*info)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Add("Content-Type", "application/json")
		fmt.Fprintf(w, "{ \"token\": \"%s\"}", jwtToken)

	})
	mux := http.NewServeMux()
	mux.Handle("/api/", http.StripPrefix("/api", apiRouter))
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, auth.RedirectUrl(), http.StatusTemporaryRedirect)
	})
	mux.Handle("/", http.FileServerFS(assets))

	log.Printf("listening on port [%d]\n", 8080)
	if err := http.ListenAndServe(":8080", loggerWrap(mux)); err != nil {
		log.Fatalln(err)
	}
}
