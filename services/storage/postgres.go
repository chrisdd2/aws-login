package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"database/sql"

	"github.com/chrisdd2/aws-login/appconfig"
	_ "github.com/jackc/pgx/v5/stdlib"
)

const (
	schemaVersionTable = "aws_login_schema_table"
	rolesTable         = "roles"
	usersTable         = "users"
	userRolesTable     = "user_roles"
	accountsTable      = "accounts"
	policiesTable      = "policies"
)

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(ctx context.Context, cfg *appconfig.AppConfig) (*PostgresStore, error) {
	pgCfg := cfg.Storage.Postgres
	if pgCfg.Port == 0 {
		pgCfg.Port = 5432
	}
	if pgCfg.Host == "" {
		pgCfg.Host = "localhost"
	}
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		pgCfg.Username, pgCfg.Password, pgCfg.Host, pgCfg.Port, pgCfg.Database,
	)

	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}

	store := &PostgresStore{db: db}
	if err := store.prepareDb(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (p *PostgresStore) prepareDb(ctx context.Context) error {
	var version string
	err := p.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT version FROM %s LIMIT 1`, schemaVersionTable),
	).Scan(&version)

	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return p.v1Schema(ctx)
		}
		if err == sql.ErrNoRows {
			return p.v1Schema(ctx)
		}
		return err
	}

	if version != "1" {
		return errors.New("invalid schema version")
	}
	return nil
}
func (p *PostgresStore) v1Schema(ctx context.Context) error {
	queries := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			aws_account_id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL
		)`, accountsTable),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			name TEXT PRIMARY KEY,
			max_session_duration INT NOT NULL,
			managed_policies TEXT,
			policies TEXT,
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		)`, rolesTable),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			document TEXT NOT NULL
		)`, policiesTable),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			name TEXT PRIMARY KEY,
			superuser BOOLEAN NOT NULL DEFAULT FALSE,
			friendly_name TEXT
		)`, usersTable),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			user_name TEXT NOT NULL,
			role_name TEXT NOT NULL,
			account_name TEXT NOT NULL,
			permissions TEXT NOT NULL
		)`, userRolesTable),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			version TEXT PRIMARY KEY
		)`, schemaVersionTable),

		fmt.Sprintf(`INSERT INTO %s(version)
			SELECT '1' WHERE NOT EXISTS (SELECT 1 FROM %s)`,
			schemaVersionTable, schemaVersionTable),
	}

	for _, q := range queries {
		if _, err := p.db.ExecContext(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (p *PostgresStore) ListRolesForAccount(ctx context.Context, accountName string) ([]*appconfig.Role, error) {
	rows, err := p.db.QueryContext(ctx,
		fmt.Sprintf(`
			SELECT name, policies, managed_policies, max_session_duration
			FROM %s
			WHERE enabled = TRUE
		`, rolesTable),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []*appconfig.Role

	for rows.Next() {
		var (
			name              string
			policies          sql.NullString
			managedPolicies   sql.NullString
			maxSessionSeconds int
		)

		if err := rows.Scan(&name, &policies, &managedPolicies, &maxSessionSeconds); err != nil {
			return nil, err
		}

		ret = append(ret, &appconfig.Role{
			Name:               name,
			Policies:           parseMap(policies.String),
			ManagedPolicies:    parseArray(managedPolicies.String),
			MaxSessionDuration: time.Duration(maxSessionSeconds) * time.Second,
			Enabled:            true,
		})
	}

	return ret, nil
}

func parseArray(v string) []string {
	return strings.Split(v, ",")
}
func parseMap(v string) map[string]string {
	ret := map[string]string{}
	for i := range strings.SplitSeq(v, ",") {
		k, v, ok := strings.Cut(i, ":")
		if !ok {
			continue
		}
		ret[k] = v
	}
	return ret
}

func (p *PostgresStore) ListRolePermissions(
	ctx context.Context,
	userName string,
	roleName string,
	accountName string,
) ([]*appconfig.RoleUserAttachment, error) {

	rows, err := p.db.QueryContext(ctx,
		fmt.Sprintf(`
			SELECT permissions
			FROM %s
			WHERE user_name = $1
			  AND role_name = $2
			  AND account_name = $3
		`, userRolesTable),
		userName, roleName, accountName,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []*appconfig.RoleUserAttachment

	for rows.Next() {
		var perms string
		if err := rows.Scan(&perms); err != nil {
			return nil, err
		}

		ret = append(ret, &appconfig.RoleUserAttachment{
			RoleName:    roleName,
			AccountName: accountName,
			Permissions: parseArray(perms),
		})
	}

	return ret, nil
}

func (p *PostgresStore) GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error) {
	row := p.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT id, document FROM %s WHERE id = $1`, policiesTable),
		id,
	)

	var pid, doc string
	if err := row.Scan(&pid, &doc); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &appconfig.InlinePolicy{
		Id:       pid,
		Document: doc,
	}, nil
}

func (p *PostgresStore) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	row := p.db.QueryRowContext(ctx,
		fmt.Sprintf(`
			SELECT name, managed_policies, roles, max_session_duration
			FROM %s
			WHERE name = $1
		`, rolesTable),
		name,
	)

	var (
		rName              string
		managedPoliciesStr sql.NullString
		policiesStr        sql.NullString
		maxSessionInt      int
	)

	if err := row.Scan(&rName, &managedPoliciesStr, &policiesStr, &maxSessionInt); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &appconfig.Role{
		Name:               rName,
		ManagedPolicies:    parseArray(managedPoliciesStr.String),
		Policies:           parseMap(policiesStr.String),
		MaxSessionDuration: time.Duration(maxSessionInt) * time.Second,
		Enabled:            true,
	}, nil
}

func (p *PostgresStore) GetUser(ctx context.Context, name string) (*appconfig.User, error) {
	row := p.db.QueryRowContext(ctx,
		fmt.Sprintf(`
			SELECT name, superuser, friendly_name
			FROM %s
			WHERE name = $1
		`, usersTable),
		name,
	)

	var (
		uName        string
		superuser    bool
		friendlyName sql.NullString
	)

	if err := row.Scan(&uName, &superuser, &friendlyName); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &appconfig.User{
		Name:         uName,
		Superuser:    superuser,
		FriendlyName: friendlyName.String,
	}, nil
}

func (p *PostgresStore) GetAccount(ctx context.Context, accountName string) (*appconfig.Account, error) {
	row := p.db.QueryRowContext(ctx,
		fmt.Sprintf(`
			SELECT aws_account_id, name
			FROM %s
			WHERE name = $1
		`, accountsTable),
		accountName,
	)

	var acctID, name string
	if err := row.Scan(&acctID, &name); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &appconfig.Account{
		AwsAccountId: acctID,
		Name:         name,
	}, nil
}

func (p *PostgresStore) ListAccounts(ctx context.Context) ([]*appconfig.Account, error) {
	rows, err := p.db.QueryContext(ctx,
		fmt.Sprintf(`SELECT aws_account_id, name FROM %s`, accountsTable),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []*appconfig.Account

	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}

		ret = append(ret, &appconfig.Account{
			AwsAccountId: id,
			Name:         name,
		})
	}

	return ret, nil
}

func (p *PostgresStore) Reload(ctx context.Context) error {
	// No in-memory cache yet
	return nil
}

func (p *PostgresStore) PrettyPrint(ctx context.Context) (string, error) {
	return "PostgresStore: no pretty printer implemented", nil
}
