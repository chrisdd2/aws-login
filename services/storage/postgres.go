package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"strings"
	"time"

	"database/sql"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	ErrInvalidSchemaVersion = errors.New("invalid schema version")
)

const (
	schemaVersionTable = "aws_login_schema_table"
	rolesTable         = "aws_login_roles"
	usersTable         = "aws_login_users"
	userRolesTable     = "aws_login_user_roles"
	accountsTable      = "aws_login_accounts"
	policiesTable      = "aws_login_policies"
	eventsTable        = "aws_login_events"
)

type PostgresStore struct {
	db  *sql.DB
	cfg *appconfig.AppConfig
}

func NewPostgresStore(ctx context.Context, cfg *appconfig.AppConfig) (*PostgresStore, error) {
	pgCfg := cfg.Storage.Postgres
	if pgCfg.Port == 0 {
		pgCfg.Port = 5432
	}
	if pgCfg.Host == "" {
		pgCfg.Host = "localhost"
	}
	username := url.QueryEscape(pgCfg.Username)
	password := url.QueryEscape(pgCfg.Password)
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		username, password, pgCfg.Host, pgCfg.Port, pgCfg.Database,
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, err
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}

	store := &PostgresStore{db: db, cfg: cfg}
	if err := store.prepareDb(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

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
			return p.v2Schema(ctx)
		}
		if err == sql.ErrNoRows {
			return p.v1Schema(ctx)
		}
		return err
	}
	switch version {
	case "1":
		log.Println("updating to v2 schema")
		return p.v2Schema(ctx)
	case "2":
		return nil
	}
	return ErrInvalidSchemaVersion
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
	rows, err := p.query(ctx,
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
			name            string
			policies        sql.NullString
			managedPolicies sql.NullString
			maxSessionInt   sql.NullInt64
		)

		if err := rows.Scan(&name, &policies, &managedPolicies, &maxSessionInt); err != nil {
			return nil, err
		}
		ret = append(ret, &appconfig.Role{
			Name:               name,
			Policies:           TextMap{}.Scan(policies.String),
			ManagedPolicies:    parseArray(managedPolicies.String),
			MaxSessionDuration: time.Duration(maxSessionInt.Int64),
			Enabled:            true,
		})
	}

	return ret, nil
}

func parseArray(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return strings.Split(v, ",")
}

type TextMap map[string]string

func (tm TextMap) Scan(v string) map[string]string {
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
func (tm TextMap) Serialize() string {
	ret := ""
	for k, v := range tm {
		ret += fmt.Sprintf("%s:%s,", k, v)
	}
	return ret
}

func (p *PostgresStore) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	log.Println(query)
	return p.db.QueryContext(ctx, query, args...)
}
func (p *PostgresStore) queryFmt(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return p.db.QueryContext(ctx, fmt.Sprintf(query, args...))
}

func (p *PostgresStore) adminRoles(ctx context.Context, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error) {
	q := fmt.Sprintf("SELECT name, roles FROM %s WHERE 2 > 1", accountsTable)
	if accountName != "" {
		q += fmt.Sprintf(" AND name = '%s'", accountName)
	}
	rows, err := p.query(ctx, q)
	if err != nil {
		return nil, err
	}
	ret := []appconfig.RoleUserAttachment{}
	for rows.Next() {
		var name, roles sql.NullString
		if err := rows.Scan(&name, &roles); err != nil {
			return nil, err
		}
		for role := range strings.SplitSeq(roles.String, ",") {
			role = strings.TrimSpace(role)
			if role == "" || (roleName != "" && roleName != role) {
				continue
			}
			ret = append(ret, appconfig.RoleUserAttachment{RoleName: role, AccountName: name.String, Permissions: appconfig.RolePermissionAll})
		}
	}
	log.Println(ret)
	return ret, nil
}

func (p *PostgresStore) ListRolePermissions(
	ctx context.Context,
	userName string,
	roleName string,
	accountName string,
) ([]appconfig.RoleUserAttachment, error) {
	usr, err := p.GetUser(ctx, userName)
	if err != nil {
		return nil, err
	}
	if userName == p.cfg.Auth.AdminUsername || usr.Superuser {
		return p.adminRoles(ctx, roleName, accountName)
	}
	query := []string{
		fmt.Sprintf("SELECT a.role_name,a.account_name, a.permissions FROM %s a WHERE 2 > 1", userRolesTable),
	}
	args := []any{}
	idx := 1
	query = append(query, fmt.Sprintf("AND user_name = $%d", idx))
	args = append(args, userName)
	idx++
	if accountName != "" {
		query = append(query, fmt.Sprintf("AND account_name = $%d", idx))
		args = append(args, accountName)
		idx++
	}
	if roleName != "" {
		query = append(query, fmt.Sprintf("AND role_name = $%d", idx))
		args = append(args, roleName)
		idx++
	}

	rows, err := p.query(ctx, strings.Join(query, " "), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []appconfig.RoleUserAttachment

	for rows.Next() {
		var perms string
		if err := rows.Scan(&perms); err != nil {
			return nil, err
		}

		ret = append(ret, appconfig.RoleUserAttachment{
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
			return nil, err
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
			SELECT name, managed_policies, policies, max_session_duration
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
			return nil, err
		}
		return nil, err
	}
	return &appconfig.Role{
		Name:               rName,
		ManagedPolicies:    parseArray(managedPoliciesStr.String),
		Policies:           TextMap{}.Scan(policiesStr.String),
		MaxSessionDuration: time.Duration(maxSessionInt),
		Enabled:            true,
	}, nil
}

func (p *PostgresStore) GetUser(ctx context.Context, name string) (*appconfig.User, error) {
	var rows *sql.Rows
	var err error
	if name == p.cfg.Auth.AdminUsername {
		roles, err := p.adminRoles(ctx, "", "")
		if err != nil {
			return nil, err
		}
		return &appconfig.User{
			FriendlyName: name,
			Name:         name,
			Superuser:    true,
			Roles:        roles,
		}, nil
	}
	rows, err = p.query(ctx,
		fmt.Sprintf(`
			SELECT a.name, a.superuser, a.friendly_name, b.account_name, b.role_name, b.permissions
			FROM %s a
			LEFT JOIN %s b
			ON a.name = b.user_name or a.superuser
			WHERE a.name = $1
		`, usersTable, userRolesTable),
		name,
	)
	if err != nil {
		return nil, err
	}

	var (
		uName        string
		superuser    bool
		friendlyName sql.NullString
	)
	roles := []appconfig.RoleUserAttachment{}
	for rows.Next() {
		var (
			roleName    sql.NullString
			accountName sql.NullString
			permissions sql.NullString
		)
		if err := rows.Scan(&uName, &superuser, &friendlyName, &roleName, &accountName, &permissions); err != nil {
			return nil, err
		}
		roles = append(roles, appconfig.RoleUserAttachment{RoleName: roleName.String, AccountName: accountName.String, Permissions: parseArray(permissions.String)})
	}
	if uName == "" {
		return nil, ErrUserNotFound
	}

	return &appconfig.User{
		Name:         uName,
		Superuser:    superuser,
		FriendlyName: friendlyName.String,
		Roles:        roles,
	}, nil
}

func (p *PostgresStore) GetAccount(ctx context.Context, accountName string) (*appconfig.Account, error) {
	row := p.db.QueryRowContext(ctx,
		fmt.Sprintf(`
			SELECT aws_account_id, name, roles, enabled
			FROM %s
			WHERE name = $1
		`, accountsTable),
		accountName,
	)

	var acctID, name, roles string
	var enabled bool
	if err := row.Scan(&acctID, &name, &roles, &enabled); err != nil {
		if err == sql.ErrNoRows {
			return nil, err
		}
		return nil, err
	}

	return &appconfig.Account{
		AwsAccountId: acctID,
		Name:         name,
		Roles:        parseArray(roles),
		Enabled:      enabled,
	}, nil
}

func (p *PostgresStore) ListAccounts(ctx context.Context) ([]*appconfig.Account, error) {
	rows, err := p.query(ctx,
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

func (p *PostgresStore) Display(ctx context.Context) (map[string]string, error) {
	// try to convert the database into a filestore
	userRoles := map[string][]appconfig.RoleUserAttachment{}
	rows, err := p.queryFmt(ctx, "SELECT user_name,role_name,account_name,permissions FROM %s", userRolesTable)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var userName, roleName, accountName, permissions string
		err := rows.Scan(&userName, &roleName, &accountName, &permissions)
		if err != nil {
			return nil, err
		}
		userRoles[userName] = append(userRoles[userName], appconfig.RoleUserAttachment{RoleName: roleName, AccountName: accountName, Permissions: parseArray(permissions)})
	}
	users := []appconfig.User{}
	rows, err = p.queryFmt(ctx, "SELECT name,superuser,friendly_name FROM %s", usersTable)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, friendlyName string
		var superuser bool
		err := rows.Scan(&name, &superuser, &friendlyName)
		if err != nil {
			return nil, err
		}
		users = append(users, appconfig.User{FriendlyName: friendlyName, Name: name, Roles: userRoles[name], Superuser: superuser})
	}
	policies := []appconfig.InlinePolicy{}
	rows, err = p.queryFmt(ctx, "SELECT id,document FROM %s", policiesTable)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var id, document string
		err := rows.Scan(&id, &document)
		if err != nil {
			return nil, err
		}
		policies = append(policies, appconfig.InlinePolicy{Id: id, Document: document})
	}
	accounts := []appconfig.Account{}
	rows, err = p.queryFmt(ctx, "SELECT aws_account_id,name,roles,enabled FROM %s", accountsTable)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var awsAccountId, name, roles string
		var enabled bool
		err := rows.Scan(&awsAccountId, &name, &roles, &enabled)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, appconfig.Account{Name: name, AwsAccountId: awsAccountId, Enabled: enabled, Roles: parseArray(roles)})
	}

	roles := []appconfig.Role{}
	rows, err = p.queryFmt(ctx, "SELECT name,max_session_duration,managed_policies,policies,enabled FROM %s", rolesTable)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var (
			name                      string
			managedPolicies, policies sql.NullString
			maxSessionDuration        int64
			enabled                   bool
		)
		err := rows.Scan(&name, &maxSessionDuration, &managedPolicies, &policies, &enabled)
		if err != nil {
			return nil, err
		}
		roles = append(roles, appconfig.Role{
			Name:               name,
			Policies:           TextMap{}.Scan(policies.String),
			ManagedPolicies:    parseArray(managedPolicies.String),
			MaxSessionDuration: time.Duration(maxSessionDuration),
			Enabled:            enabled,
		})
	}
	s := &FileStore{Users: users, Accounts: accounts, Policies: policies, Roles: roles}

	return s.Display(ctx)
}

func (p *PostgresStore) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	b, _ := json.Marshal(metadata)
	if b == nil {
		b = []byte{'{', '}'}
	}
	if _, err := p.db.ExecContext(ctx,
		fmt.Sprintf("INSERT INTO %s(id,time,event_type,metadata) VALUES($1,$2,$3,$4)", eventsTable), uuid.NewString(), time.Now().UTC().String(), eventType, string(b)); err != nil {
		return err
	}
	return nil
}

func (p *PostgresStore) Import(ctx context.Context, r io.Reader) error {
	fs := FileStore{}
	if err := fs.LoadYaml(r); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	for _, policy := range fs.Policies {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE id = $1", policiesTable),
			policy.Id); err != nil {
			return fmt.Errorf("failed to delete policy %s: %w", policy.Id, err)
		}
		if policy.Delete {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s(id, document) VALUES($1, $2)", policiesTable),
			policy.Id, policy.Document); err != nil {
			return fmt.Errorf("failed to insert policy %s: %w", policy.Id, err)
		}
	}

	for _, role := range fs.Roles {
		policiesStr := TextMap(role.Policies).Serialize()
		managedPoliciesStr := strings.Join(role.ManagedPolicies, ",")
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE name = $1", rolesTable),
			role.Name); err != nil {
			return fmt.Errorf("failed to delete role %s: %w", role.Name, err)
		}
		if role.Delete {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s(name, max_session_duration, managed_policies, policies, enabled) VALUES($1, $2, $3, $4, $5)", rolesTable),
			role.Name, int(role.MaxSessionDuration), managedPoliciesStr, policiesStr, role.Enabled); err != nil {
			return fmt.Errorf("failed to insert role %s: %w", role.Name, err)
		}
	}

	for _, account := range fs.Accounts {
		rolesStr := strings.Join(account.Roles, ",")
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE name = $1", accountsTable),
			account.Name); err != nil {
			return fmt.Errorf("failed to delete account %s: %w", account.Name, err)
		}
		if account.Delete {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s(aws_account_id, name, roles, enabled) VALUES($1, $2, $3, $4)", accountsTable),
			account.AwsAccountId, account.Name, rolesStr, account.Enabled); err != nil {
			return fmt.Errorf("failed to insert account %s: %w", account.Name, err)
		}
	}

	for _, user := range fs.Users {
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE user_name = $1", userRolesTable),
			user.Name); err != nil {
			return fmt.Errorf("failed to delete user role attachments for %s: %w", user.Name, err)
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE name = $1", usersTable),
			user.Name); err != nil {
			return fmt.Errorf("failed to delete user %s: %w", user.Name, err)
		}
		if user.Delete {
			continue
		}
		if _, err := tx.ExecContext(ctx,
			fmt.Sprintf("INSERT INTO %s(name, superuser, friendly_name) VALUES($1, $2, $3)", usersTable),
			user.Name, user.Superuser, user.FriendlyName); err != nil {
			return fmt.Errorf("failed to insert user %s: %w", user.Name, err)
		}

		for _, roleAttachment := range user.Roles {
			permissionsStr := strings.Join(roleAttachment.Permissions, ",")
			if _, err := tx.ExecContext(ctx,
				fmt.Sprintf("INSERT INTO %s(user_name, role_name, account_name, permissions) VALUES($1, $2, $3, $4)", userRolesTable),
				user.Name, roleAttachment.RoleName, roleAttachment.AccountName, permissionsStr); err != nil {
				return fmt.Errorf("failed to insert user role attachment for %s: %w", user.Name, err)
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
