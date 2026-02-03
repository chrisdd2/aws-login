package store

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"strings"
)

const (
	schemaVersionTable = "aws_login_schema_table"
	rolesTable         = "aws_login_roles"
	usersTable         = "aws_login_users"
	userRolesTable     = "aws_login_user_roles"
	accountsTable      = "aws_login_accounts"
	policiesTable      = "aws_login_policies"
	eventsTable        = "aws_login_events"
	roleAccountTable   = "aws_login_role_accounts"
	rolePolicyTable    = "aws_login_role_policies"
)

const (
	resourceTable            = "aws_login_resources"
	resourceAttachmentsTable = "aws_login_res_attachments"
	userPermissionsTable     = "aws_login_user_permissions"
)

type pgSchema struct{ db *sql.DB }

func (p *pgSchema) migrate(ctx context.Context) error {
	for {
		var version string
		err := p.db.QueryRowContext(ctx,
			fmt.Sprintf(`SELECT max(version) as version FROM %s LIMIT 1`, schemaVersionTable),
		).Scan(&version)

		if err != nil {
			if !strings.Contains(err.Error(), "does not exist") {
				return fmt.Errorf("db.QueryRowContext: %w", err)
			}
			version = "0"
		}
		switch version {
		case "0":
			slog.Info("storage", "pg", "upgrading to v1")
			err = p.v6Schema(ctx, false)
		case "1":
			slog.Info("storage", "pg", "upgrading to v2")
			err = p.v2Schema(ctx)
		case "2":
			slog.Info("storage", "pg", "upgrading to v3")
			err = p.v3Schema(ctx)
		case "3":
			slog.Info("storage", "pg", "upgrading to v4")
			err = p.v4Schema(ctx)
		case "4":
			slog.Info("storage", "pg", "upgrading to v5")
			err = p.v5Schema(ctx)
		case "5":
			slog.Info("storage", "pg", "upgrading to v6")
			err = p.v6Schema(ctx, true)
		case "6":
			return nil
		default:
			return ErrInvalidSchemaVersion
		}
		if err != nil {
			return fmt.Errorf("v%sSchema: %w", version, err)
		}
	}
}

func (p *pgSchema) v6Schema(ctx context.Context, existing bool) error {
	queries := []string{
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s(id text,type text, document text, metadata text,disabled bool, UNIQUE(type,id))", resourceTable),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s(resource_id text,target_resource_id text, type text, metadata text,disabled bool,UNIQUE(type,resource_id,target_resource_id))", resourceAttachmentsTable),
		fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s(user_id text,resource_id text,account_id text, type text, permissions text,metadata text,disabled bool, UNIQUE(type,user_id,resource_id,account_id))", userPermissionsTable),
	}
	if existing {
		queries = append(queries,
			fmt.Sprintf("INSERT INTO %s(id,disabled,metadata,type,document) SELECT name,disabled,'','account',json_build_object( 'aws_account_id', aws_account_id) FROM %s", resourceTable, accountsTable),
			fmt.Sprintf("INSERT INTO %s(id,disabled,metadata,type) SELECT name,disabled,'friendly_name:' || friendly_name, 'user' FROM %s", resourceTable, usersTable),
			fmt.Sprintf("INSERT INTO %s(id,disabled,metadata,type,document) SELECT id,disabled,'', 'policy',document FROM %s", resourceTable, policiesTable),
			fmt.Sprintf(`INSERT INTO %s(id,disabled,metadata,type,document) SELECT name,disabled,metadata,'role',json_build_object( 'managed_policies', string_to_array(managed_policies, ','), 'max_session_duration', max_session_duration::text) FROM %s`, resourceTable, rolesTable),

			// attach
			fmt.Sprintf(`INSERT INTO %s(resource_id,target_resource_id,disabled,metadata,type) SELECT role_name,policy_id,disabled,metadata,'policy' FROM %s`, resourceAttachmentsTable, rolePolicyTable),
			fmt.Sprintf(`INSERT INTO %s(resource_id,target_resource_id,disabled,metadata,type) SELECT role_name,account_name,disabled,metadata,'role' FROM %s`, resourceAttachmentsTable, roleAccountTable),

			// perm
			fmt.Sprintf(`INSERT INTO %s(user_id,resource_id,account_id,disabled,metadata,type,permissions) SELECT user_name,role_name,account_name,disabled,metadata,'role',permissions FROM %s`, userPermissionsTable, userRolesTable),
			fmt.Sprintf(`INSERT INTO %s(user_id,resource_id,account_id,disabled,metadata,type,permissions) SELECT name,'','',false,'','superuser','' FROM %s WHERE superuser`, userPermissionsTable, usersTable),
		)
	}
	return p.executeVersion(ctx, 6, queries...)
}

func (p *pgSchema) v5Schema(ctx context.Context) error {
	return p.executeVersion(ctx, 5,
		fmt.Sprintf("ALTER TABLE %s ADD UNIQUE (name,aws_account_id)", accountsTable),
	)
}

func (p *pgSchema) v4Schema(ctx context.Context) error {
	return p.executeVersion(ctx, 4,
		fmt.Sprintf("ALTER TABLE %s ADD UNIQUE (role_name,policy_id)", rolePolicyTable),
		fmt.Sprintf("ALTER TABLE %s ADD UNIQUE (role_name,account_name)", roleAccountTable),
		fmt.Sprintf("ALTER TABLE %s ADD UNIQUE (role_name,account_name,user_name)", userRolesTable),
	)
}

func (p *pgSchema) executeVersion(ctx context.Context, version int, queries ...string) error {
	for _, q := range queries {
		if _, err := p.db.ExecContext(ctx, q); err != nil {
			return fmt.Errorf("db.ExecContext: %w", err)
		}
	}
	if _, err := p.db.ExecContext(ctx, fmt.Sprintf(`INSERT INTO %s(version) SELECT %d`, schemaVersionTable, version)); err != nil {
		return fmt.Errorf("db.ExecContext: %w", err)
	}
	return nil
}

func (p *pgSchema) v3Schema(ctx context.Context) error {
	return p.executeVersion(ctx, 3,
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
	)
}

func (p *pgSchema) v2Schema(ctx context.Context) error {
	return p.executeVersion(ctx, 2,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			id TEXT PRIMARY KEY,
			time TEXT NOT NULL,
			event_type TEXT NOT NULL,
			metadata TEXT DEFAULT '{}'
	)`, eventsTable))
}
func (p *pgSchema) v1Schema(ctx context.Context) error {
	return p.executeVersion(ctx, 1,
		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			aws_account_id TEXT PRIMARY KEY,
			name TEXT UNIQUE NOT NULL,
			roles TEXT,
			enabled bool NOT NULL DEFAULT TRUE
		)`, accountsTable),

		fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
			name TEXT PRIMARY KEY,
			max_session_duration BIGINT NOT NULL,
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
	)
}
