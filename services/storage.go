package services

import (
	"context"
	"iter"

	"github.com/chrisdd2/aws-login/appconfig"
)

type Storage interface {
	GetRole(ctx context.Context, id string) (*appconfig.Role, error)
	GetRoles(ctx context.Context, id ...string) ([]*appconfig.Role, error)

	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
	GetAccounts(ctx context.Context, id ...string) ([]*appconfig.Account, error)
	ListAccounts(ctx context.Context, nextToken *string) (iter.Seq[*appconfig.Account], *string, error)
	GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (*appconfig.Account, error)

	GetUser(ctx context.Context, id string) (*appconfig.User, error)
	GetUsers(ctx context.Context, id ...string) ([]*appconfig.User, error)
	ListUsers(ctx context.Context, nextToken *string) (iter.Seq[*appconfig.User], *string, error)
	GetUserByName(ctx context.Context, name string) (*appconfig.User, error)
}
