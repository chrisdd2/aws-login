package storage

import (
	"context"
	"iter"
	"strconv"
	"time"
)

type Account struct {
	Id           string            `json:"id,omitempty"`
	AwsAccountId int               `json:"aws_account_id,omitempty"`
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

type AccountService interface {
	GetAccount(ctx context.Context, id ...string) ([]*Account, error)
	GetAccountByAwsAccountId(ctx context.Context, accountId int) (*Account, error)
	PutAccount(ctx context.Context, acc *Account, delete bool) (*Account, error)
	ListAccounts(ctx context.Context, token *string) (accounts iter.Seq[*Account], nextToken *string, err error)
}
