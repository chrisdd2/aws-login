package storage

import (
	"context"

	"github.com/chrisdd2/aws-login/appconfig"
)

type PostgresStore struct {
}

func (p *PostgresStore) ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error) {
	return nil, nil
}

func (p *PostgresStore) ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]*appconfig.RoleUserAttachment, error) {
	return nil, nil
}
func (p *PostgresStore) GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error) {
	return nil, nil
}
func (p *PostgresStore) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	return nil, nil
}

func (p *PostgresStore) GetUser(ctx context.Context, name string) (*appconfig.User, error) {
	return nil, nil
}

func (p *PostgresStore) GetAccount(ctx context.Context, id string) (*appconfig.Account, error) {
	return nil, nil
}

func (p *PostgresStore) ListAccounts(ctx context.Context) ([]*appconfig.Account, error) {
	return nil, nil
}

func (p *PostgresStore) Reload(ctx context.Context) error { return nil }

func (p *PostgresStore) PrettyPrint(ctx context.Context) (string, error) { return "", nil }
