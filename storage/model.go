package storage

import (
	"strconv"
	"time"
)

// generate implementation for backends
//go:generate go run gen.go

type RolePermissionType int
type AccountPermissionType int

const (
	RolePermissionInvalid = 0
	RolePermissionLogin   = RolePermissionType(iota) + 1
	RolePermissionCredential
	RolePermissionGrant

	AccountPermissionInvalid   = 0
	AccountPermissionBootstrap = AccountPermissionType(iota) + 1
	AccountPermissionStatus
)

type Role struct {
	Id                 string            `json:"id,omitempty" sg:"id"`
	AccountId          string            `json:"account_id,omitempty" sg:"list"`
	Name               string            `json:"name,omitempty"`
	Policies           map[string]string `json:"inline_policies,omitempty"`
	ManagedPolicies    []string          `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration     `json:"max_session_duration,omitempty"`
	Enabled            bool              `json:"enabled,omitempty"`
}

type RolePermission struct {
	AccountId string             `json:"account_id,omitempty" sg:"lookup=1,functionName=HasRolePermission,existsOnly,list,cmp"`
	UserId    string             `json:"user_id,omitempty" sg:"lookup=1,id,skipget,list,cmp"`
	RoleId    string             `json:"role_id,omitempty" sg:"lookup=1,cmp"`
	Type      RolePermissionType `json:"type,omitempty" sg:"lookup=1,cmp"`
}

type AccountPermission struct {
	AccountId string                `json:"account_id,omitempty" sg:"lookup=1,functionName=HasAccountPermission,existsOnly,list,cmp"`
	UserId    string                `json:"user_id,omitempty" sg:"lookup=1,id,skipget,list,cmp"`
	Type      AccountPermissionType `json:"type,omitempty" sg:"lookup=1,cmp"`
}
type Account struct {
	Id           string            `json:"id,omitempty" sg:"id"`
	AwsAccountId int               `json:"aws_account_id,omitempty" sg:"lookup=1,functionName=GetAccountByAwsAccountId,cmp"`
	Name         string            `json:"friendly_name,omitempty"`
	Enabled      bool              `json:"enabled,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
	// meta
	SyncTime   time.Time `json:"last_sync,omitempty"`
	SyncBy     string    `json:"last_sync_by,omitempty"`
	UpdateTime time.Time `json:"update_time,omitempty"`
	UpdateBy   string    `json:"update_by,omitempty"`
}

func (a *Account) AccountIdStr() string {
	return strconv.Itoa(a.AwsAccountId)
}

type User struct {
	Id        string `json:"id,omitempty" sg:"id"`
	Name      string `json:"name,omitempty" sg:"lookup=1,functionName=GetUserByName,cmp"`
	Email     string `json:"email,omitempty"`
	Tags      string `json:"tags,omitempty"`
	Superuser bool   `json:"superuser,omitempty"`
}

type OAuthClient struct {
	ClientId     string   `json:"client_id,omitempty" sg:"id"`
	ClientSecret string   `json:"client_secret,omitempty"`
	Accounts     []string `json:"accounts,omitempty"`
	RedirectUrls []string `json:"redirect_urls,omitempty"`
}

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
