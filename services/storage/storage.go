package storage

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
)

var ErrUserNotFound = errors.New("UserNotFound")

type Reloadable interface {
	Reload(ctx context.Context) error
}

type Printable interface {
	Display(ctx context.Context) (map[string]string, error)
}

type Importable interface {
	Import(ctx context.Context, reader io.Reader) error
}

type Storage interface {
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)

	ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error)
	GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error)

	GetRole(ctx context.Context, name string) (*appconfig.Role, error)
	GetUser(ctx context.Context, name string) (*appconfig.User, error)
	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)
}
type Event struct {
	Id       string            `json:"id,omitempty"`
	Time     time.Time         `json:"time"`
	Type     string            `json:"type,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

type Eventer interface {
	Publish(ctx context.Context, eventType string, metadata map[string]string) error
}

type ConsoleEventer struct{}

func (c ConsoleEventer) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	slog.Info("event", "type", eventType, "metadata", metadata)
	return nil
}

type NoopStorage struct{}

func (n NoopStorage) Reload(ctx context.Context) error {
	return nil
}

func (n NoopStorage) Display(ctx context.Context) (map[string]string, error) {
	return map[string]string{}, nil
}

func (n NoopStorage) Import(ctx context.Context, r io.Reader) error {
	return nil
}
