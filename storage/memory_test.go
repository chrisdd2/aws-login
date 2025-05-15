package storage_test

import (
	"context"
	"testing"

	"github.com/chrisdd2/aws-login/storage"
	"github.com/stretchr/testify/require"
)

func TestSimple(t *testing.T) {
	ctx := context.Background()
	m := storage.NewMemoryStorage()
	usr, err := m.PutUser(ctx, storage.User{
		Email: "me@me.com",
		Label: "its me",
	})
	require.NoError(t, err)
	require.NotEmpty(t, usr.Id)

	acc, err := m.PutAccount(ctx, storage.Account{AwsAccountId: 123456789123, FriendlyName: "mine"})
	require.NoError(t, err)
	require.NotEmpty(t, acc.Id)

	err = m.PutUserPermission(ctx, storage.UserPermission{
		UserPermissionId: storage.UserPermissionId{
			UserId:    usr.Id,
			AccountId: acc.Id,
			Scope:     "ASSUME",
		},
		Value: []string{"*"},
	})
	require.NoError(t, err)

	accounts := []string{}
	result, err := m.ListAccountsForUser(ctx, usr.Id, nil)
	require.NoError(t, err)
	for _, acc := range result.Accounts {
		accounts = append(accounts, acc.Id)
	}
	require.Len(t, accounts, 1)
	require.Equal(t, accounts[0], acc.Id)

}
