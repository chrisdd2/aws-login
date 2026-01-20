package pg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"database/sql"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services/storage"
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
	roleAccountTable   = "aws_login_role_accounts"
	rolePolicyTable    = "aws_login_role_policies"
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
		return nil, fmt.Errorf("sql.Open: %w", err)
	}

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("db.PingContext: %w", err)
	}

	store := &PostgresStore{db: db, cfg: cfg}
	if err := store.prepareDb(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("PostgresStore.prepareDb: %w", err)
	}
	return store, nil
}

func (p *PostgresStore) ListRolesForAccount(ctx context.Context, accountName string) ([]*appconfig.Role, error) {
	ats, err := p.ListRoleAccountAttachments(ctx, "", accountName)
	if err != nil {
		return nil, fmt.Errorf("ListRoleAccountAttachments: %w", err)
	}
	ret := make([]*appconfig.Role, 0, len(ats))
	for _, at := range ats {
		role, err := p.GetRole(ctx, at.RoleName)
		if err != nil {
			return nil, fmt.Errorf("GetRole: %w", err)
		}
		ret = append(ret, role)
	}
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
		return nil, fmt.Errorf("GetUser: %w", err)
	}
	if userName == p.cfg.Auth.AdminUsername || usr.Superuser {
		ats, err := p.ListRoleAccountAttachments(ctx, roleName, accountName)
		if err != nil {
			return nil, fmt.Errorf("ListRoleAccountAttachments: %w", err)
		}
		ret := make([]appconfig.RoleUserAttachment, 0, len(ats))
		for _, at := range ats {
			ret = append(ret, appconfig.RoleUserAttachment{
				RoleUserAttachmentId: appconfig.RoleUserAttachmentId{
					Username:    userName,
					RoleName:    at.RoleName,
					AccountName: at.AccountName,
				},
				Permissions: appconfig.RolePermissionAll})
		}
		return ret, nil
	}
	return p.ListRoleUserAttachments(ctx, userName, roleName, accountName)
}

func (p *PostgresStore) GetPolicy(ctx context.Context, id string) (*appconfig.Policy, error) {
	items, err := scan[appconfig.Policy](ctx, p.db, policiesTable, "id =$1", id)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	if len(items) < 1 {
		return nil, storage.ErrPolicyNotFound
	}
	return &items[0], nil
}

func (p *PostgresStore) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	items, err := scan[appconfig.Role](ctx, p.db, rolesTable, "name = $1", name)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	if len(items) < 1 {
		return nil, storage.ErrRoleNotFound
	}
	return &items[0], nil
}

func (p *PostgresStore) GetUser(ctx context.Context, name string) (*appconfig.User, error) {
	if name == p.cfg.Auth.AdminUsername {
		return &appconfig.User{
			FriendlyName: name,
			Name:         name,
			Superuser:    true,
			CommonFields: appconfig.CommonFields{Disabled: false},
		}, nil
	}
	items, err := scan[appconfig.User](ctx, p.db, usersTable, "name = $1", name)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	if len(items) < 1 {
		return nil, storage.ErrUserNotFound
	}
	return &items[0], nil
}

func (p *PostgresStore) GetAccount(ctx context.Context, accountName string) (*appconfig.Account, error) {
	items, err := scan[appconfig.Account](ctx, p.db, accountsTable, "name = $1", accountName)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	if len(items) < 1 {
		return nil, storage.ErrAccountNotFound
	}
	return &items[0], nil
}

func (p *PostgresStore) ListAccounts(ctx context.Context) ([]appconfig.Account, error) {
	return scan[appconfig.Account](ctx, p.db, accountsTable, "")
}

func (p *PostgresStore) Reload(ctx context.Context) error {
	// No in-memory cache yet
	return nil
}

func (p *PostgresStore) Display(ctx context.Context) (*storage.InMemoryStore, error) {
	// try to convert the database into a inmemory store
	roleUserAttachments, err := scan[appconfig.RoleUserAttachment](ctx, p.db, userRolesTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	roleAccountAttachments, err := scan[appconfig.RoleAccountAttachment](ctx, p.db, roleAccountTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	rolePolicyAttachments, err := scan[appconfig.RolePolicyAttachment](ctx, p.db, rolePolicyTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	users, err := scan[appconfig.User](ctx, p.db, usersTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	accounts, err := scan[appconfig.Account](ctx, p.db, accountsTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	roles, err := scan[appconfig.Role](ctx, p.db, rolesTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	policies, err := scan[appconfig.Policy](ctx, p.db, policiesTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	s := storage.InMemoryStore{
		Accounts:               accounts,
		Users:                  users,
		Roles:                  roles,
		Policies:               policies,
		RolePolicyAttachments:  rolePolicyAttachments,
		RoleUserAttachments:    roleUserAttachments,
		RoleAccountAttachments: roleAccountAttachments,
	}

	return s.Display(ctx)
}

func (p *PostgresStore) Publish(ctx context.Context, eventType string, metadata map[string]string) error {
	slog.Info("event", "type", eventType, "metadata", metadata)
	b, err := json.Marshal(metadata)
	if err != nil || b == nil{
		// Fallback to empty object if marshaling fails
		b = []byte{'{', '}'}
	}
	if _, err := p.db.ExecContext(ctx,
		fmt.Sprintf("INSERT INTO %s(id,time,event_type,metadata) VALUES($1,$2,$3,$4)", eventsTable), uuid.NewString(), time.Now().UTC().String(), eventType, string(b)); err != nil {
		return fmt.Errorf("db.ExecContext: %w", err)
	}
	return nil
}

func (p *PostgresStore) ListUsers(ctx context.Context) ([]string, error) {
	users, err := scan[appconfig.User](ctx, p.db, usersTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	ret := []string{}
	for _, usr := range users {
		ret = append(ret, usr.Name)
	}
	return ret, nil
}

func (p *PostgresStore) ListPolicies(ctx context.Context) ([]string, error) {
	items, err := scan[appconfig.Policy](ctx, p.db, policiesTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	ret := []string{}
	for _, item := range items {
		ret = append(ret, item.Id)
	}
	return ret, nil
}

func (p *PostgresStore) ListRoles(ctx context.Context) ([]string, error) {
	items, err := scan[appconfig.Role](ctx, p.db, rolesTable, "")
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}
	ret := []string{}
	for _, item := range items {
		ret = append(ret, item.Name)
	}
	return ret, nil
}

func (p *PostgresStore) PutUser(ctx context.Context, u *appconfig.User) error {
	return put(ctx, p.db, u, usersTable, u.Delete)
}

func (p *PostgresStore) PutAccount(ctx context.Context, a *appconfig.Account) error {
	return put(ctx, p.db, a, accountsTable, a.Delete)
}

func (p *PostgresStore) PutRole(ctx context.Context, r *appconfig.Role) error {
	return put(ctx, p.db, r, rolesTable, r.Delete)
}

func (p *PostgresStore) PutPolicy(ctx context.Context, pol *appconfig.Policy) error {
	return put(ctx, p.db, pol, policiesTable, pol.Delete)
}

func (p *PostgresStore) PutRoleAccountAttachment(ctx context.Context, ra *appconfig.RoleAccountAttachment) error {
	return put(ctx, p.db, ra, roleAccountTable, ra.Delete)
}

func (p *PostgresStore) PutRolePolicyAttachment(ctx context.Context, rp *appconfig.RolePolicyAttachment) error {
	return put(ctx, p.db, rp, rolePolicyTable, rp.Delete)
}

func (p *PostgresStore) PutRoleUserAttachment(ctx context.Context, ru *appconfig.RoleUserAttachment) error {
	return put(ctx, p.db, ru, userRolesTable, ru.Delete)
}

func (p *PostgresStore) ListRoleAccountAttachments(ctx context.Context, roleName, accountName string) ([]appconfig.RoleAccountAttachment, error) {
	if accountName == "" && roleName == "" {
		return scan[appconfig.RoleAccountAttachment](ctx, p.db, roleAccountTable, "")
	}
	if roleName == "" {
		return scan[appconfig.RoleAccountAttachment](ctx, p.db, roleAccountTable, "account_name =$1", accountName)
	}
	return scan[appconfig.RoleAccountAttachment](ctx, p.db, roleAccountTable, "account_name = $1 and role_name = $2", accountName, roleName)
}
func (p *PostgresStore) ListRoleUserAttachments(ctx context.Context, username string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error) {
	if roleName == "" && accountName == "" && username == "" {
		return scan[appconfig.RoleUserAttachment](ctx, p.db, userRolesTable, "")
	}
	if roleName == "" && accountName == "" {
		return scan[appconfig.RoleUserAttachment](ctx, p.db, userRolesTable, "user_name = $1", username)
	}
	return scan[appconfig.RoleUserAttachment](ctx, p.db, userRolesTable, "user_name = $1 and role_name = $2 and account_name = $3", username, roleName, accountName)
}
func (p *PostgresStore) ListRolePolicyAttachments(ctx context.Context, roleName string) ([]appconfig.RolePolicyAttachment, error) {
	return scan[appconfig.RolePolicyAttachment](ctx, p.db, rolePolicyTable, "role_name = $1", roleName)
}
