package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/chrisdd2/aws-login/storage"
)

type captureStatusCodeWriter struct {
	http.ResponseWriter
	statusCode int
	buf        io.Writer
}

func (w *captureStatusCodeWriter) Write(data []byte) (int, error) {
	if w.statusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.buf.Write(data)
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
		writer := captureStatusCodeWriter{ResponseWriter: w, buf: &bytes.Buffer{}}
		// cors
		w.Header().Set("Access-Control-Allow-Origin", "*")
		handler.ServeHTTP(&writer, r)
		log.Printf("%s: %d %s %s data: %s\n", r.RemoteAddr, writer.statusCode, r.Method, r.URL.Path, writer.buf)
	})
}

type blockNotFoundWriter struct {
	http.ResponseWriter
	didBlock bool
}

func (b *blockNotFoundWriter) Write(data []byte) (int, error) {
	if b.didBlock {
		return len(data), nil
	}
	return b.ResponseWriter.Write(data)
}

func (b *blockNotFoundWriter) WriteHeader(statusCode int) {
	if statusCode != http.StatusNotFound {
		b.ResponseWriter.WriteHeader(statusCode)
		return
	}
	b.didBlock = true
}
func contentTypeHtml(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
}
func contentTypeJson(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
}
func writeHtml(w http.ResponseWriter, v []byte) (int, error) {
	contentTypeHtml(w)
	return w.Write(v)
}

func writeJson(w http.ResponseWriter, v any) {
	contentTypeJson(w)
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		log.Println(err)
	}
}
