package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/chrisdd2/aws-login/storage"
)

type CaptureStatusCodeWriter struct {
	http.ResponseWriter
	StatusCode int
	buf        io.Writer
}

func (w *CaptureStatusCodeWriter) Write(data []byte) (int, error) {
	if w.StatusCode == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.StatusCode == http.StatusInternalServerError {
		w.buf.Write(data)
	}
	return w.ResponseWriter.Write(data)
}

func (w *CaptureStatusCodeWriter) WriteHeader(statusCode int) {
	w.StatusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func LoadStorage(file string) (*storage.MemoryStorage, error) {
	f, err := os.Open(file)
	if err != nil {
		log.Println(err)
		return storage.NewMemoryStorage(), nil
	}
	defer f.Close()
	return storage.NewMemoryStorageFromJson(f)
}

func LoggerWrap(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := CaptureStatusCodeWriter{ResponseWriter: w, buf: &bytes.Buffer{}}
		// cors
		w.Header().Set("Access-Control-Allow-Origin", "*")
		handler.ServeHTTP(&writer, r)
		log.Printf("%s: %d %s %s data: %s\n", r.RemoteAddr, writer.StatusCode, r.Method, r.URL.Path, writer.buf)
	})
}

type BlockNotFoundWriter struct {
	http.ResponseWriter
	didBlock bool
}

func (b *BlockNotFoundWriter) Write(data []byte) (int, error) {
	if b.didBlock {
		return len(data), nil
	}
	return b.ResponseWriter.Write(data)
}

func (b *BlockNotFoundWriter) WriteHeader(statusCode int) {
	if statusCode != http.StatusNotFound {
		b.ResponseWriter.WriteHeader(statusCode)
		return
	}
	b.didBlock = true
}
func ContentTypeHtml(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
}
func ContentTypeJson(w http.ResponseWriter) {
	w.Header().Add("Content-Type", "application/json")
}
func WriteHtml(w http.ResponseWriter, v []byte) (int, error) {
	ContentTypeHtml(w)
	return w.Write(v)
}

func WriteJson(w http.ResponseWriter, v any) {
	ContentTypeJson(w)
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		log.Println(err)
	}
}
