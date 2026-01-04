package appconfig

import (
	"time"
)

const (
	RolePermissionInvalid     = "invalid"
	RolePermissionCredentials = "credential"
	RolePermissionConsole     = "console"
)

var RolePermissionAll []string = []string{RolePermissionConsole, RolePermissionCredentials}

type InlinePolicy struct {
	Id       string `json:"id,omitempty"`
	Document string `json:"document,omitempty"`
}

type Role struct {
	Name               string            `json:"name,omitempty"`
	Policies           map[string]string `json:"inline_policies,omitempty"`
	ManagedPolicies    []string          `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration     `json:"max_session_duration,omitempty"`
	Enabled            bool              `json:"enabled,omitempty"`
}

type RoleUserAttachment struct {
	RoleName    string   `json:"role_name,omitempty"`
	AccountName string   `json:"account_name,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}
type User struct {
	FriendlyName string               `json:"friendly_name,omitempty"`
	Name         string               `json:"name,omitempty"`
	Superuser    bool                 `json:"superuser,omitempty"`
	Roles        []RoleUserAttachment `json:"roles,omitempty"`
}

type Account struct {
	Name         string   `json:"name,omitempty"`
	AwsAccountId string   `json:"aws_account_id,omitempty"`
	Enabled      bool     `json:"enabled,omitempty"`
	Roles        []string `json:"roles,omitempty"`
}
