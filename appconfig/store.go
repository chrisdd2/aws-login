package appconfig

import (
	"encoding/json"
	"io"
	"slices"
	"time"

	"github.com/goccy/go-yaml"
)

type InlinePolicy struct {
	Id       string
	Document string
}

type Role struct {
	Name               string            `json:"name,omitempty"`
	Policies           map[string]string `json:"inline_policies,omitempty"`
	ManagedPolicies    []string          `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration     `json:"max_session_duration,omitempty"`
	Enabled            bool              `json:"enabled,omitempty"`
	AssociatedAccounts []string          `json:"accounts,omitempty"`
}
type RoleAttachment struct {
	RoleName    string
	AccountName string
	Permissions []string
}
type User struct {
	Name      string           `json:"name,omitempty"`
	Email     string           `json:"email,omitempty"`
	Superuser bool             `json:"superuser,omitempty"`
	Roles     []RoleAttachment `json:"roles,omitempty"`
}
type Account struct {
	Name         string `json:"friendly_name,omitempty"`
	AwsAccountId int    `json:"aws_account_id,omitempty"`
	Enabled      bool   `json:"enabled,omitempty"`
}

type Store struct {
	Users    []User    `json:"users,omitempty"`
	Accounts []Account `json:"accounts,omitempty"`
	Roles    []Role    `json:"roles,omitempty"`
}

func (s *Store) Merge(o *Store) *Store {
	return &Store{
		Users:    slices.Concat(s.Users, o.Users),
		Accounts: slices.Concat(s.Accounts, o.Accounts),
		Roles:    slices.Concat(s.Roles, o.Roles),
	}
}
func (s *Store) LoadYaml(r io.Reader) error {
	return yaml.NewDecoder(r).Decode(&s)
}
func (s *Store) LoadJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&s)
}
