package appconfig

import (
	"fmt"
	"strconv"
	"time"
)

const (
	RolePermissionInvalid     = "invalid"
	RolePermissionCredentials = "credential"
	RolePermissionConsole     = "console"
)

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
	AssociatedAccounts []string          `json:"accounts,omitempty"`
}

func (r Role) Arn(accountId int) string {
	return fmt.Sprintf("arn:aws:iam::%d:role/%s", accountId, r.Name)
}

type RoleAttachment struct {
	RoleName    string   `json:"role_name,omitempty"`
	AccountName string   `json:"account_name,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
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

func (a Account) AccountId() string {
	return strconv.Itoa(a.AwsAccountId)
}
