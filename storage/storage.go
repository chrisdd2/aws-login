package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/chrisdd2/aws-login/aws"
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

func (acc Account) Roles() []string {
	return []string{aws.ReadOnlyRole, aws.DeveloperRole}
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

type Storage interface {
	// read
	ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error)
	ListPermissions(ctx context.Context, userId string, accountId string, permissionType string, scope string, startToken *string) (ListPermissionResult, error)
	ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error)
	ListAccountsForUser(ctx context.Context, userId string, startToken *string) (ListAccountResult, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserById(ctx context.Context, userId string) (User, error)
	BatchGetUserById(ctx context.Context, userId ...string) ([]User, error)
	GetAccountById(ctx context.Context, accountId string) (Account, error)
	GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (Account, error)

	// write
	PutAccount(ctx context.Context, acc Account, delete bool) (Account, error)
	PutUser(ctx context.Context, usr User, delete bool) (User, error)
	PutRolePermission(ctx context.Context, perm Permission, delete bool) error
}

var ErrUserNotFound = errors.New("user not found")
var ErrAccountNotFound = errors.New("account not found")
var ErrAccountAlreadyExists = errors.New("account already exists")
var ErrInvalidAccountDetails = errors.New("invalid account details")
