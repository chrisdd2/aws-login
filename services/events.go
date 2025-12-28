package services

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/google/uuid"
)

type Event struct {
	Id       string            `json:"id,omitempty"`
	Time     time.Time         `json:"time,omitempty"`
	Type     string            `json:"type,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type Eventer interface {
	Publish(ctx context.Context, eventType string, metadata map[string]string) error
}

type fileEventer struct {
	f *os.File
	w *bufio.Writer
}

func (f *fileEventer) Close() {
	f.w.Flush()
	f.f.Close()
}
func (f *fileEventer) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	b, err := json.Marshal(Event{
		Id:       uuid.NewString(),
		Time:     time.Now().UTC(),
		Type:     eventType,
		Metadata: metadata,
	})
	if err != nil {
		return err
	}
	f.w.Write(b)
	f.w.WriteByte('\n')
	return f.w.Flush()
}

func NewFileEventer(filename string) (*fileEventer, error) {
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		return nil, err
	}
	return &fileEventer{f, bufio.NewWriter(f)}, nil
}
