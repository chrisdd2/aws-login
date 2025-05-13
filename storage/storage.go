package storage

import (
	"context"
	"errors"
)

type User struct {
	Id    string `json:"id,omitempty"`
	Email string `json:"email,omitempty"`
	Label string `json:"label,omitempty"`
	Tags  string `json:"tags,omitempty"`
}
type Account struct {
	Id                string            `json:"id,omitempty"`
	AwsAccountId      int               `json:"aws_account_id,omitempty"`
	ManagementRoleArn string            `json:"management_role_arn,omitempty"`
	Roles             []string          `json:"roles,omitempty"`
	FriendlyName      string            `json:"friendly_name,omitempty"`
	Tags              map[string]string `json:"tags,omitempty"`
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
	Users      []User
	StartToken *string
}
type ListUserPermissionResult struct {
	UserPermissions []UserPermission
	StartToken      *string
}
type ListAccountResult struct {
	Accounts   []Account
	StartToken *string
}

type Storage interface {
	// read
	ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error)
	ListUserPermissions(ctx context.Context, userId string, accountId string, scope string, startToken *string) (ListUserPermissionResult, error)
	ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error)
	ListAccountsForUser(ctx context.Context, userId string, startToken *string) (ListAccountResult, error)
	GetUserByEmail(ctx context.Context, email string) (User, error)

	// write
	PutAccount(ctx context.Context, acc Account) (Account, error)
	PutUser(ctx context.Context, usr User) (User, error)
	PutUserPermission(ctx context.Context, perm UserPermission) error
	DeleteUserBy(ctx context.Context, email string) error
	DeleteUser(ctx context.Context, userId string) error
}

var ErrUserNotFound = errors.New("not found")
