package store

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"log"
	"net/url"
	"strings"

	"database/sql"

	"github.com/chrisdd2/aws-login/appconfig"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var (
	ErrInvalidSchemaVersion = errors.New("invalid schema version")
)

type PostgresStore struct {
	db  *sql.DB
	cfg *appconfig.AppConfig
}

var _postgresStore Store = &PostgresStore{}

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
	schema := pgSchema{db}
	if err := schema.migrate(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("pgSchema.migrate: %w", err)
	}
	return store, nil
}

type Scannable[T any] interface {
	*T
	Scan() []any
}

func query[T any, PT Scannable[T]](ctx context.Context, db *sql.DB, query string, args ...any) ([]*T, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ret := []*T{}
	for rows.Next() {
		v := *new(T)
		if err := rows.Scan(PT(&v).Scan()...); err != nil {
			return nil, err
		}
		ret = append(ret, &v)
	}
	return ret, nil
}

func (p *PostgresStore) GetResources(ctx context.Context, resourceType string, ids ...string) ([]*Resource, error) {
	flt := andFlt{}
	flt.addEq("type", resourceType)
	flt.addIn("id", ids)
	q := fmt.Sprintf("SELECT * FROM %s%s", resourceTable, flt.String())
	log.Println(q, resourceType, ids)
	return query[Resource](ctx, p.db, q, flt.Args()...)
}
func (p *PostgresStore) SearchResources(ctx context.Context, resourceTypes ...string) (iter.Seq[*Resource], error) {
	flt := andFlt{}
	flt.addIn("type", resourceTypes)
	q := fmt.Sprintf("SELECT * FROM %s%s", resourceTable, flt.String())
	ret, err := query[Resource](ctx, p.db, q, flt.Args()...)
	if err != nil {
		return nil, err
	}
	return func(yield func(*Resource) bool) {
		for _, r := range ret {
			if !yield(r) {
				break
			}
		}
	}, nil
}
func (p *PostgresStore) GetResourceAttachments(ctx context.Context, attachmentType, resourceId, accountId string) ([]*ResourceAttachment, error) {
	flt := andFlt{}
	flt.addEq("type", attachmentType)
	flt.addEq("resource_id", resourceId)
	flt.addEq("target_resource_id", accountId)
	q := fmt.Sprintf("SELECT * FROM %s%s", resourceAttachmentsTable, flt.String())
	return query[ResourceAttachment](ctx, p.db, q, flt.Args()...)
}
func (p *PostgresStore) GetUserPermission(ctx context.Context, permissionType, userId, resourceId, accountId string) ([]*UserPermission, error) {
	flt := andFlt{}
	flt.addEq("type", permissionType)
	flt.addEq("user_id", userId)
	flt.addEq("resource_id", resourceId)
	flt.addEq("account_id", accountId)
	q := fmt.Sprintf("SELECT * FROM %s%s", userPermissionsTable, flt.String())
	log.Println(q, flt.Args())
	return query[UserPermission](ctx, p.db, q, flt.Args()...)
}

func (p *PostgresStore) PutResource(ctx context.Context, objs ...*Resource) error {
	columns := []string{
		"id", "type", "document", "metadata", "disabled",
	}
	id := columns[0]
	values := []string{}
	updates := []string{}
	for i, c := range columns {
		values = append(values, fmt.Sprintf("$%d", i+1))
		updates = append(updates, fmt.Sprintf("%s = $%d", c, i+1))
	}
	q := fmt.Sprintf("INSERT INTO %s(%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
		resourceTable, strings.Join(columns, ","), strings.Join(values, ","), id, strings.Join(updates[1:], ","),
	)
	log.Println(q)
	stmt, err := p.db.PrepareContext(ctx, q)
	if err != nil {
		return nil
	}
	defer stmt.Close()
	for _, obj := range objs {
		if _, err := stmt.ExecContext(ctx,
			obj.Id, obj.Type, obj.Document, obj.Metadata, obj.Disabled,
		); err != nil {
			return err
		}
	}
	return nil
}

func (p *PostgresStore) PutResourceAttachment(ctx context.Context, objs ...*ResourceAttachment) error {
	columns := []string{
		"resource_id", "target_resource_id", "type", "metadata", "disabled",
	}
	id := columns[0:2]
	values := []string{}
	updates := []string{}
	for i, c := range columns {
		values = append(values, fmt.Sprintf("$%d", i+1))
		updates = append(updates, fmt.Sprintf("%s = $%d", c, i+1))
	}
	q := fmt.Sprintf("INSERT INTO %s(%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
		resourceTable, strings.Join(columns, ","), strings.Join(values, ","), strings.Join(id, ","), strings.Join(updates[2:], ","),
	)
	log.Println(q)
	stmt, err := p.db.PrepareContext(ctx, q)
	if err != nil {
		return nil
	}
	defer stmt.Close()
	for _, obj := range objs {
		if _, err := stmt.ExecContext(ctx,
			obj.ResourceId, obj.TargetResourceId, obj.Type, obj.Metadata, obj.Disabled,
		); err != nil {
			return err
		}
	}
	return nil
}

func (p *PostgresStore) PutUserPermission(ctx context.Context, objs ...*UserPermission) error {
	columns := []string{
		"user_id", "resource_id", "account_id", "type", "metadata", "disabled",
	}
	id := columns[0:3]
	values := []string{}
	updates := []string{}
	for i, c := range columns {
		values = append(values, fmt.Sprintf("$%d", i+1))
		updates = append(updates, fmt.Sprintf("%s = $%d", c, i+1))
	}
	q := fmt.Sprintf("INSERT INTO %s(%s) VALUES (%s) ON CONFLICT (%s) DO UPDATE SET %s",
		resourceTable, strings.Join(columns, ","), strings.Join(values, ","), strings.Join(id, ","), strings.Join(updates[3:], ","),
	)
	log.Println(q)
	stmt, err := p.db.PrepareContext(ctx, q)
	if err != nil {
		return nil
	}
	defer stmt.Close()
	for _, obj := range objs {
		if _, err := stmt.ExecContext(ctx,
			obj.ResourceId, obj.AccountId, obj.Type, obj.Metadata, obj.Disabled,
		); err != nil {
			return err
		}
	}
	return nil
}

type andFlt struct {
	sb   strings.Builder
	args []any
}

func (f *andFlt) addEq(col string, value any) {
	if value == "" {
		return
	}
	f.args = append(f.args, value)
	fmt.Fprintf(&f.sb, " AND %s=$%d", col, len(f.args))
}
func (f *andFlt) addIn(col string, arr []string) {
	if len(arr) == 0 {
		return
	}
	f.args = append(f.args, arr)
	f.sb.WriteString(fmt.Sprintf(" AND %s = ANY($%d)", col, len(f.args)))
}
func (f *andFlt) String() string {
	if len(f.args) == 0 {
		return ""
	}
	return fmt.Sprintf(" WHERE 2 > 1%s", f.sb.String())
}
func (f *andFlt) Args() []any {
	return f.args
}
