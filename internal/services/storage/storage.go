package storage

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
)

var (
	ErrUserNotFound    = errors.New("UserNotFound")
	ErrPolicyNotFound  = errors.New("PolicyNotFound")
	ErrAccountNotFound = errors.New("AccountNotFound")
	ErrRoleNotFound    = errors.New("RoleNotFound")
)

type Reloadable interface {
	Reload(ctx context.Context) error
}

type Printable interface {
	Display(ctx context.Context) (*InMemoryStore, error)
}

type Writeable interface {
	PutUser(ctx context.Context, u *appconfig.User, del bool) error
	PutAccount(ctx context.Context, a *appconfig.Account, del bool) error
	PutRole(ctx context.Context, r *appconfig.Role, del bool) error
	PutPolicy(ctx context.Context, p *appconfig.InlinePolicy, del bool) error
}

type Readable interface {
	GetRole(ctx context.Context, name string) (*appconfig.Role, error)
	GetUser(ctx context.Context, name string) (*appconfig.User, error)
	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)
	ListUsers(ctx context.Context) ([]string, error)
	ListPolicies(ctx context.Context) ([]string, error)
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)
	GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error)
}

type Storage interface {
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)
	ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error)
	Readable
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

func (n NoopStorage) Display(ctx context.Context) (*InMemoryStore, error) {
	return &InMemoryStore{}, nil
}

func (n NoopStorage) Import(ctx context.Context, st *InMemoryStore) error {
	return nil
}

type InMemoryStore struct {
	Users    []appconfig.User         `json:"users,omitempty"`
	Accounts []appconfig.Account      `json:"accounts,omitempty"`
	Roles    []appconfig.Role         `json:"roles,omitempty"`
	Policies []appconfig.InlinePolicy `json:"policies,omitempty"`
}

func (s *InMemoryStore) Display(ctx context.Context) (*InMemoryStore, error) {
	return s, nil
}
