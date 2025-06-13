package storage

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
)

type User struct {
	Id        string `json:"id,omitempty"`
	Username  string `json:"username,omitempty"`
	Email     string `json:"email,omitempty"`
	Tags      string `json:"tags,omitempty"`
	Superuser bool   `json:"superuser,omitempty"`
}

type Account struct {
	Id           string            `json:"id,omitempty"`
	AwsAccountId int               `json:"aws_account_id,omitempty"`
	FriendlyName string            `json:"friendly_name,omitempty"`
	Enabled      bool              `json:"enabled,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

type Role struct {
	Id                 string            `json:"id,omitempty"`
	RoleName           string            `json:"role_name,omitempty"`
	Policies           map[string]string `json:"inline_policies,omitempty"`
	ManagedPolicies    []string          `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration     `json:"max_session_duration,omitempty"`
	Enabled            bool              `json:"enabled,omitempty"`
}

func (acc Account) ArnForRole(roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%d:role/%s", acc.AwsAccountId, roleName)
}

type PermissionId struct {
	UserId    string `json:"user_id,omitempty"`
	AccountId string `json:"account_id,omitempty"`
	Type      string `json:"type,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

const (
	AccountAdminPermission        = "ADMIN"
	AccountAdminScopeAccount      = "ACCOUNT"
	AccountAdminPermissionEnabled = "ENABLED"

	RolePermission       = "ROLE"
	RolePermissionAssume = "ASSUME"
	RolePermissionGrant  = "GRANT"
)

type Permission struct {
	PermissionId
	Value []string `json:"value,omitempty"`
}
type ListUserResult struct {
	Users      []User  `json:"user"`
	StartToken *string `json:"start_token,omitempty"`
}
type ListPermissionResult struct {
	Permissions []Permission `json:"permissions"`
	StartToken  *string      `json:"start_token,omitempty"`
}
type ListAccountResult struct {
	Accounts   []Account `json:"accounts"`
	StartToken *string   `json:"start_token,omitempty"`
}
type ListRoleItem struct {
	RoleId   string `json:"role_id,omitempty"`
	RoleName string `json:"role_name,omitempty"`
}
type ListRolesForAccount struct {
	Roles      []ListRoleItem `json:"roles,omitempty"`
	StartToken *string        `json:"start_token,omitempty"`
}

type Storage interface {
	// read
	ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error)
	ListPermissions(ctx context.Context, userId string, accountId string, permissionType string, scope string, startToken *string) (ListPermissionResult, error)
	ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error)
	ListRolesForAccount(ctx context.Context, accountId string, startToken *string) (ListRolesForAccount, error)
	ListAccountsForUser(ctx context.Context, userId string, startToken *string) (ListAccountResult, error)

	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserById(ctx context.Context, userId string) (User, error)
	BatchGetUserById(ctx context.Context, userId ...string) ([]User, error)
	GetAccountById(ctx context.Context, accountId string) (Account, error)
	GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (Account, error)
	GetRoleById(ctx context.Context, roleId string) (Role, error)
	GetRoleByName(ctx context.Context, roleName string) (Role, error)
	BatchGetRolesById(ctx context.Context, roleId ...string) ([]Role, error)

	// write
	PutAccount(ctx context.Context, acc Account, delete bool) (Account, error)
	PutUser(ctx context.Context, usr User, delete bool) (User, error)
	PutRolePermission(ctx context.Context, perm Permission, delete bool) error
	PutRole(ctx context.Context, role Role, delete bool) (Role, error)
	PutRoleAssociation(ctx context.Context, accountId string, roleId string, delete bool) error
}

var ErrUserNotFound = errors.New("user not found")
var ErrRoleNotFound = errors.New("role not found")
var ErrAccountNotFound = errors.New("account not found")
var ErrAccountAlreadyExists = errors.New("account already exists")
var ErrInvalidAccountDetails = errors.New("invalid account details")

func GetDeveloperRole() Role {
	return Role{
		RoleName:           DeveloperRole,
		MaxSessionDuration: time.Hour * 8,
		Enabled:            true,
		ManagedPolicies: []string{
			"arn:aws:iam::aws:policy/AdministratorAccess",
		},
	}
}
func GetReadOnlyRole() Role {
	return Role{
		RoleName:           ReadOnlyRole,
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

type AwsRole string

func (d AwsRole) String() string {
	if d == DeveloperRole {
		return "developer"
	}
	if d == ReadOnlyRole {
		return "read-only"
	}
	return string(d)
}

func (d AwsRole) RealName() string {
	if d == "developer" {
		return DeveloperRole
	}
	if d == "read-only" {
		return ReadOnlyRole
	}
	return string(d)

}

// Validate the account number for AWS it must be a 12 digit number
func ValidateAWSAccountIDStr(accountID string) bool {
	re := regexp.MustCompile(`^\d{12}$`)
	return re.MatchString(accountID)
}
func ValidateAWSAccountID(accountID int) bool {
	return accountID > 100000000000 && accountID <= 999999999999
}
