package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/chrisdd2/aws-login/appconfig"
	"gopkg.in/yaml.v2"
)

var ErrUserNotFound = errors.New("UserNotFound")

type Storage interface {
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)

	ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]*appconfig.RoleAttachment, error)
	GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error)

	GetRole(ctx context.Context, name string) (*appconfig.Role, error)
	GetUser(ctx context.Context, name string) (*appconfig.User, error)
	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
}

type Store struct {
	Users    []appconfig.User         `json:"users,omitempty"`
	Accounts []appconfig.Account      `json:"accounts,omitempty"`
	Roles    []appconfig.Role         `json:"roles,omitempty"`
	Policies []appconfig.InlinePolicy `json:"policies,omitempty"`
}

func (s *Store) Merge(o *Store) *Store {
	return &Store{
		Users:    slices.Concat(s.Users, o.Users),
		Accounts: slices.Concat(s.Accounts, o.Accounts),
		Roles:    slices.Concat(s.Roles, o.Roles),
		Policies: slices.Concat(s.Policies, o.Policies),
	}
}
func (s *Store) LoadYaml(r io.Reader) error {
	return yaml.NewDecoder(r).Decode(&s)
}
func (s *Store) LoadJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&s)
}

func NewStaticStore() *Store {
	return &Store{}
}

func (s *Store) GetAccount(ctx context.Context, name string) (*appconfig.Account, error) {
	idx := slices.IndexFunc(s.Accounts, func(acc appconfig.Account) bool {
		return name == acc.Name
	})
	if idx != -1 {
		return &s.Accounts[idx], nil
	}
	return nil, errors.New("AccountNotFound")
}

func (s *Store) ListRolesForAccount(ctx context.Context, accountName string) ([]*appconfig.Role, error) {
	roles := []*appconfig.Role{}
	for _, role := range s.Roles {
		if accountName == "" || slices.Contains(role.AssociatedAccounts, accountName) {
			roles = append(roles, &role)
		}
	}
	return roles, nil
}
func (s *Store) ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]*appconfig.RoleAttachment, error) {
	if userName == "" {
		return nil, errors.New("username must be provided")
	}
	user, err := s.GetUser(ctx, userName)
	if err != nil {
		return nil, fmt.Errorf("storage.GetUser: %w", err)
	}
	ats := []*appconfig.RoleAttachment{}
	for _, at := range user.Roles {
		if (accountName == "" || at.AccountName == accountName) && (roleName == "" || at.RoleName == roleName) {
			ats = append(ats, &at)
		}
	}
	return ats, nil
}
func (s *Store) GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error) {
	idx := slices.IndexFunc(s.Policies, func(acc appconfig.InlinePolicy) bool {
		return id == acc.Id
	})
	if idx != -1 {
		return &s.Policies[idx], nil
	}
	return nil, errors.New("PolicyNotFound")
}
func (s *Store) GetUser(ctx context.Context, id string) (*appconfig.User, error) {
	idx := slices.IndexFunc(s.Users, func(acc appconfig.User) bool {
		return id == acc.Name
	})
	if idx != -1 {
		return &s.Users[idx], nil
	}
	return nil, ErrUserNotFound
}

func (s *Store) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	idx := slices.IndexFunc(s.Roles, func(acc appconfig.Role) bool {
		return name == acc.Name
	})
	if idx != -1 {
		return &s.Roles[idx], nil
	}
	return nil, errors.New("RoleNotFound")
}
