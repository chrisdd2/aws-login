package services

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
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

type s3Eventer struct {
	s3             *s3.Client
	bucket         string
	key            string
	lastCommitTime time.Time
	buffered       []Event
	bufferedLock   sync.Mutex
}

func NewS3Eventer(s3Cl *s3.Client, bucket string, key string) (*s3Eventer, error) {
	return &s3Eventer{
		s3:           s3Cl,
		bucket:       bucket,
		key:          key,
		bufferedLock: sync.Mutex{},
	}, nil
}

func (s *s3Eventer) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	s.bufferedLock.Lock()
	s.buffered = append(s.buffered, Event{
		Id:       uuid.NewString(),
		Time:     time.Now().UTC(),
		Type:     eventType,
		Metadata: metadata,
	})
	s.bufferedLock.Unlock()
	return nil
}

func (s *s3Eventer) CommitLoop(ctx context.Context, commitInternal time.Duration, commitNumEventThreshold int, commitTimeWindow time.Duration) {
	done := ctx.Done()
	ticker := time.Tick(commitInternal)
	for {
		select {
		case <-done:
			return
		case <-ticker:
			if err := s.commit(ctx, commitNumEventThreshold, commitTimeWindow); err != nil {
				slog.Info("s3eventer", "commit_error", err)
			}
		}
	}
}
func (s *s3Eventer) commit(ctx context.Context, commitThreshold int, commitWindow time.Duration) error {
	if len(s.buffered) == 0 {
		return nil
	}
	if len(s.buffered) < commitThreshold && s.lastCommitTime.Sub(time.Now().UTC()) < commitWindow {
		return nil
	}
	buf := bytes.Buffer{}
	commitTime := time.Now().UTC()
	enc := json.NewEncoder(&buf)
	s.bufferedLock.Lock()
	events := s.buffered
	for _, ev := range events {
		enc.Encode(ev)
		buf.WriteByte('\n')
	}
	s.buffered = nil
	s.lastCommitTime = commitTime
	s.bufferedLock.Unlock()
	s3Key := fmt.Sprintf("%s-%d", s.key, commitTime.UnixMilli())
	if _, err := s.s3.PutObject(ctx, &s3.PutObjectInput{Body: &buf, Key: &s3Key, Bucket: &s.bucket}); err != nil {
		return err
	}
	return nil
}
