package pg

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"log/slog"
	"strings"
)

func (p *PostgresStore) prepareDb(ctx context.Context) error {
	var version string
	err := p.db.QueryRowContext(ctx,
		fmt.Sprintf(`SELECT max(version) as version FROM %s LIMIT 1`, schemaVersionTable),
	).Scan(&version)

	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			if err := p.v1Schema(ctx); err != nil {
				return err
			}
			if err := p.v2Schema(ctx); err != nil {
				return err
			}
			return p.v3Schema(ctx)
		}
		if err == sql.ErrNoRows {
			return p.v3Schema(ctx)
		}
		return err
	}
	switch version {
	case "1":
		slog.Info("storage", "pg", "upgrading to v2")
		return p.v2Schema(ctx)
	case "2":
		slog.Info("storage", "pg", "upgrading to v3")
		return p.v3Schema(ctx)
	case "3":
		return nil
	}
	return ErrInvalidSchemaVersion
}

func (p *PostgresStore) v3Schema(ctx context.Context) error {

	queries := []string{

		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s(role_name text,account_name text,disabled boolean,metadata text)", roleAccountTable),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s(role_name text,policy_id text,disabled boolean,metadata text)", rolePolicyTable),

		// migrate the data before we drop the table
		fmt.Sprintf(`INSERT INTO %s (role_name, policy_id, disabled, metadata)
		SELECT name,policy_id,false,'' FROM (SELECT name, split_part(trim(unnest(string_to_array(policies, ','))),':',2) as policy_id
		FROM %s WHERE policies IS NOT NULL AND policies != '') where policy_id != ''`, rolePolicyTable, rolesTable),
		fmt.Sprintf(`INSERT INTO %s (role_name, account_name, disabled, metadata) SELECT trim(unnest(string_to_array(roles, ','))), name, false, '' FROM %s WHERE roles IS NOT NULL AND roles != ''`, roleAccountTable, accountsTable),

		// accounts
		// move roles to role attachment
		fmt.Sprintf("ALTER TABLE %s DROP COLUMN roles", accountsTable),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN metadata TEXT", accountsTable),
		fmt.Sprintf("ALTER TABLE %s RENAME COLUMN enabled TO disabled", accountsTable),
		// // inverse all values
		fmt.Sprintf("UPDATE %s SET disabled = not disabled", accountsTable),

		// // policies
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN metadata TEXT", policiesTable),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN disabled boolean", policiesTable),

		// roles
		fmt.Sprintf("ALTER TABLE %s DROP COLUMN policies", rolesTable),
		fmt.Sprintf("ALTER TABLE %s RENAME COLUMN enabled TO disabled", rolesTable),
		// inverse all values
		fmt.Sprintf("UPDATE %s SET disabled = not disabled", rolesTable),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN metadata TEXT", rolesTable),

		// users roles
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN metadata TEXT", userRolesTable),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN disabled boolean", userRolesTable),

		// users
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN metadata TEXT", usersTable),
		fmt.Sprintf("ALTER TABLE %s ADD COLUMN disabled boolean", usersTable),
	}

	for _, q := range queries {
		if _, err := p.db.ExecContext(ctx, q); err != nil {
			log.Println(q)
			return err
		}
	}
	if _, err := p.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s(version) SELECT 3`, schemaVersionTable)); err != nil {
		return err
	}
	return nil
}

func (p *PostgresStore) v2Schema(ctx context.Context) error {
	q := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			time TEXT NOT NULL,
			event_type TEXT NOT NULL,
			metadata TEXT DEFAULT '{}'
	)`, eventsTable)
	if _, err := p.db.ExecContext(ctx, q); err != nil {
		return err
	}
	if _, err := p.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s(version) SELECT 2`, schemaVersionTable)); err != nil {
		return err
	}
	return nil
}
func (p *PostgresStore) v1Schema(ctx context.Context) error {
	queries := []string{
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			aws_account_id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			roles TEXT,
			enabled bool NOT NULL DEFAULT TRUE
		)`, accountsTable),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			name TEXT PRIMARY KEY,
			max_session_duration LONG NOT NULL,
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
