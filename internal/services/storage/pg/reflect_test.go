package pg

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/go-jose/go-jose/v4/testutils/require"
)

func TestSomething(t *testing.T) {
	ctx := t.Context()
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		"postgres", "postgres", "localhost", 5432, "postgres",
	)

	cfg := appconfig.AppConfig{}
	cfg.Storage.Type = "postgre"
	cfg.Storage.Postgres.Host = "localhost"
	cfg.Storage.Postgres.Port = 5432
	cfg.Storage.Postgres.Database = "postgres"
	cfg.Storage.Postgres.Password = "postgres"
	cfg.Storage.Postgres.Username = "postgres"

	pg, err := NewPostgresStore(ctx, &cfg)
	require.NoError(t, err)
	require.NoError(t, pg.prepareDb(ctx))

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	require.NoError(t, db.PingContext(ctx))

	accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "")
	require.NoError(t, err)
	for _, acc := range accounts {
		t.Log(acc)
	}

	t.Log(create[appconfig.RoleAccountAttachment](roleAccountTable))
	t.Log(create[appconfig.RolePolicyAttachment](rolePolicyTable))
	t.Log(create[appconfig.RoleUserAttachment](userRolesTable))
	t.Log(create[appconfig.Role](rolesTable))
	t.Log(create[appconfig.User](usersTable))
	t.Log(create[appconfig.Policy](policiesTable))
	t.Log(create[appconfig.Account](accountsTable))

	err = put(ctx, db, &appconfig.Account{Name: "hi", AwsAccountId: "1234556", CommonFields: appconfig.CommonFields{Metadata: appconfig.TextMap{"something": "hi"}}}, accountsTable, false, "Name")
	require.NoError(t, err)

}
