package storage

import (
	"context"
	"errors"
	"iter"
	"time"
)

var ErrRoleNotFound = errors.New("role not found")
var ErrUserNotFound = errors.New("user not found")
var ErrAccountNotFound = errors.New("account not found")

type Role struct {
	Id                 string            `json:"id,omitempty"`
	AccountId          string            `json:"account_id,omitempty"`
	Name               string            `json:"name,omitempty"`
	Policies           map[string]string `json:"inline_policies,omitempty"`
	ManagedPolicies    []string          `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration     `json:"max_session_duration,omitempty"`
	Enabled            bool              `json:"enabled,omitempty"`
}

type RoleService interface {
	GetRole(ctx context.Context, id ...string) ([]*Role, error)
	PutRole(ctx context.Context, role *Role, delete bool) (*Role, error)
	ListRoles(ctx context.Context, accountId string) (iter.Seq[*Role], error)
}

// defaults
func DeveloperRoleDefinition(accountId string, roleName string) *Role {
	if roleName == "" {
		roleName = DeveloperRole
	}
	return &Role{
		Name:               roleName,
		AccountId:          accountId,
		MaxSessionDuration: time.Hour * 8,
		Enabled:            true,
		ManagedPolicies: []string{
			"arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}
func ReadOnlyRoleDefinition(accountId string, roleName string) *Role {
	if roleName == "" {
		roleName = ReadOnlyRole
	}
	return &Role{
		Name:               roleName,
		AccountId:          accountId,
		MaxSessionDuration: time.Hour * 8,
		Enabled:            true,
		ManagedPolicies: []string{
			"arn:aws:iam::aws:policy/ReadOnlyAccess",
		},
	}
}

const (
	DeveloperRole = "developer-role-" + UniqueId
	ReadOnlyRole  = "read-only-role-" + UniqueId
	UniqueId      = "8db7bc11-acf5-4c7a-be46-967f44e33028"
)
