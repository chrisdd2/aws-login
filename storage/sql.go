package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

type SQLStorage struct {
	db *sql.DB
}

func NewSQLStorage(connStr string) (*SQLStorage, error) {
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	s := &SQLStorage{db: db}
	if err := s.EnsureSchema(); err != nil {
		return nil, err
	}
	return s, nil
}

// EnsureSchema checks for required tables and creates them if missing
func (s *SQLStorage) EnsureSchema() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	tableStmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT,
			tags TEXT,
			superuser BOOLEAN
		);`,
		`CREATE TABLE IF NOT EXISTS accounts (
			id TEXT PRIMARY KEY,
			aws_account_id BIGINT UNIQUE NOT NULL,
			friendly_name TEXT,
			enabled BOOLEAN,
			tags TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS permissions (
			user_id TEXT NOT NULL,
			account_id TEXT NOT NULL,
			type TEXT,
			scope TEXT,
			value TEXT,
			PRIMARY KEY (user_id, account_id, type, scope),
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
			FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS roles (
			id TEXT PRIMARY KEY,
			role_name TEXT UNIQUE NOT NULL,
			max_session_duration BIGINT,
			enabled BOOLEAN
		);`,
		`CREATE TABLE IF NOT EXISTS policies (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			content TEXT NOT NULL,
			type TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS role_policies (
			role_id TEXT NOT NULL,
			policy_id TEXT NOT NULL,
			PRIMARY KEY (role_id, policy_id),
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
			FOREIGN KEY (policy_id) REFERENCES policies(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS role_associations (
			account_id TEXT NOT NULL,
			role_id TEXT NOT NULL,
			PRIMARY KEY (account_id, role_id),
			FOREIGN KEY (account_id) REFERENCES accounts(id) ON DELETE CASCADE,
			FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
		);`,
	}
	for _, stmt := range tableStmts {
		if _, err := tx.Exec(stmt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// --- User ---

func (s *SQLStorage) ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListUserResult{}, err
	}

	query := `SELECT id, username, email, tags, superuser FROM users`
	args := []interface{}{}
	argIdx := 1

	if filter != "" {
		query += " WHERE username LIKE $1"
		argIdx++
		args = append(args, filter+"%")
	}

	query += fmt.Sprintf(" ORDER BY username LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, ListResultPageSize, startIdx)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ListUserResult{}, err
	}
	defer rows.Close()

	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Id, &u.Username, &u.Email, &u.Tags, &u.Superuser); err != nil {
			return ListUserResult{}, err
		}
		users = append(users, u)
	}

	var nextToken *string
	if len(users) == ListResultPageSize {
		nextToken = generateStartToken(startIdx + ListResultPageSize)
	}
	return ListUserResult{Users: users, StartToken: nextToken}, nil
}

func (s *SQLStorage) GetUserByUsername(ctx context.Context, username string) (User, error) {
	if username == "" {
		return User{}, ErrUserNotFound
	}
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, username, email, tags, superuser FROM users WHERE username=$1`, username).
		Scan(&u.Id, &u.Username, &u.Email, &u.Tags, &u.Superuser)
	if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	}
	return u, err
}

func (s *SQLStorage) GetUserById(ctx context.Context, userId string) (User, error) {
	if userId == "" {
		return User{}, ErrUserNotFound
	}
	var u User
	err := s.db.QueryRowContext(ctx, `SELECT id, username, email, tags, superuser FROM users WHERE id=$1`, userId).
		Scan(&u.Id, &u.Username, &u.Email, &u.Tags, &u.Superuser)
	if err == sql.ErrNoRows {
		return User{}, ErrUserNotFound
	}
	return u, err
}

func (s *SQLStorage) BatchGetUserById(ctx context.Context, userIds ...string) ([]User, error) {
	if len(userIds) == 0 {
		return nil, nil
	}
	placeholders := []string{}
	args := []interface{}{}
	for i, id := range userIds {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
		args = append(args, id)
	}
	query := fmt.Sprintf(`SELECT id, username, email, tags, superuser FROM users WHERE id IN (%s)`, strings.Join(placeholders, ","))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.Id, &u.Username, &u.Email, &u.Tags, &u.Superuser); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func (s *SQLStorage) PutUser(ctx context.Context, usr User, delete bool) (User, error) {
	if delete {
		_, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id=$1`, usr.Id)
		return usr, err
	}
	if usr.Id == "" {
		usr.Id = newUuid()
		_, err := s.db.ExecContext(ctx, `INSERT INTO users (id, username, email, tags, superuser) VALUES ($1, $2, $3, $4, $5)`,
			usr.Id, usr.Username, usr.Email, usr.Tags, usr.Superuser)
		return usr, err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE users SET username=$1, email=$2, tags=$3, superuser=$4 WHERE id=$5`,
		usr.Username, usr.Email, usr.Tags, usr.Superuser, usr.Id)
	return usr, err
}

// --- Account ---

func (s *SQLStorage) ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListAccountResult{}, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, aws_account_id, friendly_name, enabled, tags FROM accounts ORDER BY friendly_name LIMIT $1 OFFSET $2`, ListResultPageSize, startIdx)
	if err != nil {
		return ListAccountResult{}, err
	}
	defer rows.Close()
	accounts := []Account{}
	for rows.Next() {
		var a Account
		var tagsStr string
		if err := rows.Scan(&a.Id, &a.AwsAccountId, &a.FriendlyName, &a.Enabled, &tagsStr); err != nil {
			return ListAccountResult{}, err
		}
		a.Tags = parseTags(tagsStr)
		accounts = append(accounts, a)
	}
	var nextToken *string
	if len(accounts) == ListResultPageSize {
		nextToken = generateStartToken(startIdx + ListResultPageSize)
	}
	return ListAccountResult{Accounts: accounts, StartToken: nextToken}, nil
}

func (s *SQLStorage) ListAccountsForUser(ctx context.Context, userId string, startToken *string) (ListAccountResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListAccountResult{}, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.id, a.aws_account_id, a.friendly_name, a.enabled, a.tags
		FROM accounts a
		JOIN permissions p ON a.id = p.account_id
		WHERE p.user_id = $1
		ORDER BY a.friendly_name
		LIMIT $2 OFFSET $3
	`, userId, ListResultPageSize, startIdx)
	if err != nil {
		return ListAccountResult{}, err
	}
	defer rows.Close()
	accounts := []Account{}
	for rows.Next() {
		var a Account
		var tagsStr string
		if err := rows.Scan(&a.Id, &a.AwsAccountId, &a.FriendlyName, &a.Enabled, &tagsStr); err != nil {
			return ListAccountResult{}, err
		}
		a.Tags = parseTags(tagsStr)
		accounts = append(accounts, a)
	}
	var nextToken *string
	if len(accounts) == ListResultPageSize {
		nextToken = generateStartToken(startIdx + ListResultPageSize)
	}
	return ListAccountResult{Accounts: accounts, StartToken: nextToken}, nil
}

func (s *SQLStorage) GetAccountById(ctx context.Context, accountId string) (Account, error) {
	if accountId == "" {
		return Account{}, ErrAccountNotFound
	}
	var a Account
	var tagsStr string
	err := s.db.QueryRowContext(ctx, `SELECT id, aws_account_id, friendly_name, enabled, tags FROM accounts WHERE id=$1`, accountId).
		Scan(&a.Id, &a.AwsAccountId, &a.FriendlyName, &a.Enabled, &tagsStr)
	if err == sql.ErrNoRows {
		return Account{}, ErrAccountNotFound
	}
	a.Tags = parseTags(tagsStr)
	return a, err
}

func (s *SQLStorage) GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (Account, error) {
	if awsAccountId == 0 {
		return Account{}, ErrAccountNotFound
	}
	var a Account
	var tagsStr string
	err := s.db.QueryRowContext(ctx, `SELECT id, aws_account_id, friendly_name, enabled, tags FROM accounts WHERE aws_account_id=$1`, awsAccountId).
		Scan(&a.Id, &a.AwsAccountId, &a.FriendlyName, &a.Enabled, &tagsStr)
	if err == sql.ErrNoRows {
		return Account{}, ErrAccountNotFound
	}
	a.Tags = parseTags(tagsStr)
	return a, err
}

func (s *SQLStorage) PutAccount(ctx context.Context, acc Account, delete bool) (Account, error) {
	if delete {
		_, err := s.db.ExecContext(ctx, `DELETE FROM accounts WHERE id=$1`, acc.Id)
		return acc, err
	}
	tagsStr := serializeTags(acc.Tags)
	if acc.Id == "" {
		acc.Id = newUuid()
		_, err := s.db.ExecContext(ctx, `INSERT INTO accounts (id, aws_account_id, friendly_name, enabled, tags) VALUES ($1, $2, $3, $4, $5)`,
			acc.Id, acc.AwsAccountId, acc.FriendlyName, acc.Enabled, tagsStr)
		return acc, err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE accounts SET aws_account_id=$1, friendly_name=$2, enabled=$3, tags=$4 WHERE id=$5`,
		acc.AwsAccountId, acc.FriendlyName, acc.Enabled, tagsStr, acc.Id)
	return acc, err
}

// --- Permission ---

func (s *SQLStorage) ListPermissions(ctx context.Context, userId string, accountId string, permissionType string, scope string, startToken *string) (ListPermissionResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListPermissionResult{}, err
	}
	query := `SELECT user_id, account_id, type, scope, value FROM permissions WHERE 1=1`
	args := []interface{}{}
	argIdx := 1
	if userId != "" {
		query += fmt.Sprintf(" AND user_id=$%d", argIdx)
		args = append(args, userId)
		argIdx++
	}
	if accountId != "" {
		query += fmt.Sprintf(" AND account_id=$%d", argIdx)
		args = append(args, accountId)
		argIdx++
	}
	if scope != "" {
		query += fmt.Sprintf(" AND scope=$%d", argIdx)
		args = append(args, scope)
		argIdx++
	}
	if permissionType != "" {
		query += fmt.Sprintf(" AND type=$%d", argIdx)
		args = append(args, permissionType)
		argIdx++
	}
	query += fmt.Sprintf(" ORDER BY user_id, account_id, type, scope LIMIT $%d OFFSET $%d", argIdx, argIdx+1)
	args = append(args, ListResultPageSize, startIdx)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return ListPermissionResult{}, err
	}
	defer rows.Close()
	perms := []Permission{}
	for rows.Next() {
		var p Permission
		var valueStr string
		if err := rows.Scan(&p.UserId, &p.AccountId, &p.Type, &p.Scope, &valueStr); err != nil {
			return ListPermissionResult{}, err
		}
		json.Unmarshal([]byte(valueStr), &p.Value)
		perms = append(perms, p)
	}
	var nextToken *string
	if len(perms) == ListResultPageSize {
		nextToken = generateStartToken(startIdx + ListResultPageSize)
	}
	return ListPermissionResult{Permissions: perms, StartToken: nextToken}, nil
}

func (s *SQLStorage) PutPermission(ctx context.Context, perm Permission, delete bool) error {
	valueStr, _ := json.Marshal(perm.Value)
	if delete {
		_, err := s.db.ExecContext(ctx, `DELETE FROM permissions WHERE user_id=$1 AND account_id=$2 AND type=$3 AND scope=$4`,
			perm.UserId, perm.AccountId, perm.Type, perm.Scope)
		return err
	}
	// Try update first
	res, err := s.db.ExecContext(ctx, `UPDATE permissions SET value=$1 WHERE user_id=$2 AND account_id=$3 AND type=$4 AND scope=$5`,
		string(valueStr), perm.UserId, perm.AccountId, perm.Type, perm.Scope)
	if err != nil {
		return err
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		// Insert
		_, err := s.db.ExecContext(ctx, `INSERT INTO permissions (user_id, account_id, type, scope, value) VALUES ($1, $2, $3, $4, $5)`,
			perm.UserId, perm.AccountId, perm.Type, perm.Scope, string(valueStr))
		return err
	}
	return nil
}

func (s *SQLStorage) PutRole(ctx context.Context, role Role, delete bool) (Role, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return Role{}, err
	}
	defer tx.Rollback()

	if delete {
		_, err := tx.ExecContext(ctx, `DELETE FROM roles WHERE id=$1`, role.Id)
		if err != nil {
			return role, err
		}
		return role, tx.Commit()
	}

	if role.Id == "" {
		role.Id = newUuid()
		_, err := tx.ExecContext(ctx, `
			INSERT INTO roles (id, role_name, max_session_duration, enabled)
			VALUES ($1, $2, $3, $4)
		`, role.Id, role.RoleName, role.MaxSessionDuration, role.Enabled)
		if err != nil {
			return role, err
		}
	} else {
		_, err := tx.ExecContext(ctx, `
			UPDATE roles 
			SET role_name=$1, max_session_duration=$2, enabled=$3
			WHERE id=$4
		`, role.RoleName, role.MaxSessionDuration, role.Enabled, role.Id)
		if err != nil {
			return role, err
		}
	}

	// Handle inline policies
	if role.Policies != nil {
		// Delete existing inline policies
		_, err = tx.ExecContext(ctx, `
			DELETE FROM role_policies rp
			USING policies p
			WHERE rp.role_id = $1 AND rp.policy_id = p.id AND p.type = 'inline'
		`, role.Id)
		if err != nil {
			return role, err
		}

		// Insert new inline policies
		for name, content := range role.Policies {
			policyId := newUuid()
			_, err = tx.ExecContext(ctx, `
				INSERT INTO policies (id, name, content, type)
				VALUES ($1, $2, $3, 'inline')
			`, policyId, name, content)
			if err != nil {
				return role, err
			}

			_, err = tx.ExecContext(ctx, `
				INSERT INTO role_policies (role_id, policy_id)
				VALUES ($1, $2)
			`, role.Id, policyId)
			if err != nil {
				return role, err
			}
		}
	}

	// Handle managed policies
	if role.ManagedPolicies != nil {
		// Delete existing managed policies
		_, err = tx.ExecContext(ctx, `
			DELETE FROM role_policies rp
			USING policies p
			WHERE rp.role_id = $1 AND rp.policy_id = p.id AND p.type = 'managed'
		`, role.Id)
		if err != nil {
			return role, err
		}

		// Insert new managed policies
		for _, arn := range role.ManagedPolicies {
			policyId := newUuid()
			_, err = tx.ExecContext(ctx, `
				INSERT INTO policies (id, name, content, type)
				VALUES ($1, $2, $2, 'managed')
			`, policyId, arn)
			if err != nil {
				return role, err
			}

			_, err = tx.ExecContext(ctx, `
				INSERT INTO role_policies (role_id, policy_id)
				VALUES ($1, $2)
			`, role.Id, policyId)
			if err != nil {
				return role, err
			}
		}
	}

	return role, tx.Commit()
}

func (s *SQLStorage) PutRoleAssociation(ctx context.Context, accountId string, roleId string, delete bool) error {
	if delete {
		_, err := s.db.ExecContext(ctx, `DELETE FROM role_associations WHERE account_id=$1 AND role_id=$2`, accountId, roleId)
		return err
	}

	// Try to insert, ignore if already exists
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO role_associations (account_id, role_id)
		VALUES ($1, $2)
		ON CONFLICT (account_id, role_id) DO NOTHING
	`, accountId, roleId)
	return err
}

func (s *SQLStorage) ListRolesForAccount(ctx context.Context, accountId string, startToken *string) (ListRolesForAccount, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListRolesForAccount{}, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT r.id, r.role_name
		FROM roles r
		JOIN role_associations ra ON r.id = ra.role_id
		WHERE ra.account_id = $1
		ORDER BY r.role_name
		LIMIT $2 OFFSET $3
	`, accountId, ListResultPageSize, startIdx)
	if err != nil {
		return ListRolesForAccount{}, err
	}
	defer rows.Close()

	roles := []ListRoleItem{}
	for rows.Next() {
		var item ListRoleItem
		if err := rows.Scan(&item.RoleId, &item.RoleName); err != nil {
			return ListRolesForAccount{}, err
		}
		roles = append(roles, item)
	}

	var nextToken *string
	if len(roles) == ListResultPageSize {
		nextToken = generateStartToken(startIdx + ListResultPageSize)
	}
	return ListRolesForAccount{Roles: roles, StartToken: nextToken}, nil
}

func (s *SQLStorage) BatchGetRolesById(ctx context.Context, roleIds ...string) ([]Role, error) {
	if len(roleIds) == 0 {
		return nil, nil
	}

	placeholders := []string{}
	args := []interface{}{}
	for i, id := range roleIds {
		placeholders = append(placeholders, fmt.Sprintf("$%d", i+1))
		args = append(args, id)
	}

	query := fmt.Sprintf(`
		SELECT r.id, r.role_name, r.max_session_duration, r.enabled,
			   p.name as policy_name, p.content as policy_content, p.type as policy_type
		FROM roles r
		LEFT JOIN role_policies rp ON r.id = rp.role_id
		LEFT JOIN policies p ON rp.policy_id = p.id
		WHERE r.id IN (%s)
	`, strings.Join(placeholders, ","))

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	roles := make(map[string]*Role)
	for rows.Next() {
		var roleId, roleName string
		var maxSessionDuration time.Duration
		var enabled bool
		var policyName, policyContent, policyType sql.NullString

		err := rows.Scan(&roleId, &roleName, &maxSessionDuration, &enabled, &policyName, &policyContent, &policyType)
		if err != nil {
			return nil, err
		}

		role, exists := roles[roleId]
		if !exists {
			role = &Role{
				Id:                 roleId,
				RoleName:           roleName,
				MaxSessionDuration: maxSessionDuration,
				Enabled:            enabled,
				Policies:           make(map[string]string),
				ManagedPolicies:    make([]string, 0),
			}
			roles[roleId] = role
		}

		if policyName.Valid && policyContent.Valid && policyType.Valid {
			if policyType.String == "inline" {
				role.Policies[policyName.String] = policyContent.String
			} else if policyType.String == "managed" {
				role.ManagedPolicies = append(role.ManagedPolicies, policyContent.String)
			}
		}
	}

	result := make([]Role, 0, len(roles))
	for _, role := range roles {
		result = append(result, *role)
	}
	return result, nil
}

func (s *SQLStorage) GetRoleById(ctx context.Context, roleId string) (Role, error) {
	if roleId == "" {
		return Role{}, ErrRoleNotFound
	}

	roles, err := s.BatchGetRolesById(ctx, roleId)
	if err != nil {
		return Role{}, err
	}
	if len(roles) == 0 {
		return Role{}, ErrRoleNotFound
	}
	return roles[0], nil
}

func (s *SQLStorage) GetRoleByName(ctx context.Context, roleName string) (Role, error) {
	if roleName == "" {
		return Role{}, ErrRoleNotFound
	}

	var roleId string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM roles WHERE role_name = $1`, roleName).Scan(&roleId)
	if err == sql.ErrNoRows {
		return Role{}, ErrRoleNotFound
	}
	if err != nil {
		return Role{}, err
	}

	return s.GetRoleById(ctx, roleId)
}

// Tags helpers: serialize as JSON string for DB
func serializeTags(tags map[string]string) string {
	if tags == nil {
		return "{}"
	}
	b, _ := json.Marshal(tags)
	return string(b)
}

func parseTags(tagsStr string) map[string]string {
	if tagsStr == "" {
		return map[string]string{}
	}
	var tags map[string]string
	_ = json.Unmarshal([]byte(tagsStr), &tags)
	return tags
}
