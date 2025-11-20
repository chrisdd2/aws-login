package storage

import (
	"context"
	"iter"
)

type Account struct {
	Id           string            `json:"id,omitempty"`
	AwsAccountId int               `json:"aws_account_id,omitempty"`
	Name         string            `json:"friendly_name,omitempty"`
	Enabled      bool              `json:"enabled,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

type AccountService interface {
	GetAccount(ctx context.Context, id ...string) ([]*Account, error)
	GetAccountByAwsAccountId(ctx context.Context, accountId int) (*Account, error)
	PutAccount(ctx context.Context, acc *Account, delete bool) (*Account, error)
	ListAccounts(ctx context.Context) (iter.Seq[*Account], error)
}
