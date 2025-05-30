package storage

import (
	"context"
	"errors"
	"fmt"
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

func (acc Account) ArnForRole(roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%d:role/%s", acc.AwsAccountId, roleName)
}

type UserPermissionId struct {
	UserId    string `json:"user_id,omitempty"`
	AccountId string `json:"account_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
}

const (
	UserPermissionAssume = "ASSUME"
	UserPermissionAdmin  = "ADMIN"
)

type UserPermission struct {
	UserPermissionId
	Value []string `json:"value,omitempty"`
}
type ListUserResult struct {
	Users      []User  `json:"user"`
	StartToken *string `json:"start_token,omitempty"`
}
type ListUserPermissionResult struct {
	UserPermissions []UserPermission `json:"user_permissions"`
	StartToken      *string          `json:"start_token,omitempty"`
}
type ListAccountResult struct {
	Accounts   []Account `json:"accounts"`
	StartToken *string   `json:"start_token,omitempty"`
}

type Storage interface {
	// read
	ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error)
	ListUserPermissions(ctx context.Context, userId string, accountId string, scope string, startToken *string) (ListUserPermissionResult, error)
	ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error)
	ListAccountsForUser(ctx context.Context, userId string, startToken *string) (ListAccountResult, error)
	GetUserByUsername(ctx context.Context, username string) (User, error)
	GetUserById(ctx context.Context, userId string) (User, error)
	GetAccountById(ctx context.Context, accountId string) (Account, error)

	// write
	PutAccount(ctx context.Context, acc Account, delete bool) (Account, error)
	PutUser(ctx context.Context, usr User, delete bool) (User, error)
	PutUserPermission(ctx context.Context, perm UserPermission, delete bool) error
}

var ErrUserNotFound = errors.New("user not found")
var ErrAccountNotFound = errors.New("account not found")
