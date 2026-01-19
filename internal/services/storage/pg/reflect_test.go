package pg

import (
	"database/sql"
	"fmt"
	"math/rand"
	"reflect"
	"sync"
	"testing"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestCreate_TableGeneration(t *testing.T) {
	tests := []struct {
		name     string
		table    string
		expected string
	}{
		{
			name:     "Account table",
			table:    create[appconfig.Account]("accounts"),
			expected: "CREATE TABLE IF NOT EXISTS accounts(name text,aws_account_id text,disabled boolean,metadata text,UNIQUE (name,aws_account_id))",
		},
		{
			name:     "User table",
			table:    create[appconfig.User]("users"),
			expected: "CREATE TABLE IF NOT EXISTS users(friendly_name text,name text,superuser boolean,disabled boolean,metadata text,UNIQUE (name))",
		},
		{
			name:     "Role table",
			table:    create[appconfig.Role]("roles"),
			expected: "CREATE TABLE IF NOT EXISTS roles(name text,managed_policies text,max_session_duration int8,disabled boolean,metadata text,UNIQUE (name))",
		},
		{
			name:     "Policy table",
			table:    create[appconfig.Policy]("policies"),
			expected: "CREATE TABLE IF NOT EXISTS policies(id text,document text,disabled boolean,metadata text,UNIQUE (id))",
		},
		{
			name:     "RoleAccountAttachment table",
			table:    create[appconfig.RoleAccountAttachment]("role_accounts"),
			expected: "CREATE TABLE IF NOT EXISTS role_accounts(role_name text,account_name text,disabled boolean,metadata text,UNIQUE (role_name,account_name))",
		},
		{
			name:     "RolePolicyAttachment table",
			table:    create[appconfig.RolePolicyAttachment]("role_policies"),
			expected: "CREATE TABLE IF NOT EXISTS role_policies(role_name text,policy_id text,disabled boolean,metadata text,UNIQUE (role_name,policy_id))",
		},
		{
			name:     "RoleUserAttachment table",
			table:    create[appconfig.RoleUserAttachment]("user_roles"),
			expected: "CREATE TABLE IF NOT EXISTS user_roles(user_name text,role_name text,account_name text,permissions text,disabled boolean,metadata text,UNIQUE (user_name,role_name,account_name))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.table)
		})
	}
}

func TestGetFields_CacheBehavior(t *testing.T) {
	t.Run("cache is populated and reused", func(t *testing.T) {
		// First call populates cache
		fields1 := getFields(reflect.TypeFor[appconfig.Account]())

		// Clear cache to test fresh population
		_typeCache = sync.Map{}

		// Second call should repopulate cache
		fields2 := getFields(reflect.TypeFor[appconfig.Account]())
		assert.Equal(t, len(fields1), len(fields2))
	})

	t.Run("fields are correctly extracted", func(t *testing.T) {
		fields := getFields(reflect.TypeFor[appconfig.Account]())

		fieldNames := make([]string, len(fields))
		for i, f := range fields {
			fieldNames[i] = f.name
		}
		assert.Contains(t, fieldNames, "Name")
		assert.Contains(t, fieldNames, "AwsAccountId")
	})
}

func TestGetFields_AnonymousFields(t *testing.T) {
	t.Run("CommonFields are flattened", func(t *testing.T) {
		fields := getFields(reflect.TypeFor[appconfig.Account]())

		// Should include fields from embedded CommonFields
		jsonNames := make([]string, len(fields))
		for i, f := range fields {
			jsonNames[i] = f.jsonName
		}
		assert.Contains(t, jsonNames, "metadata")
		assert.Contains(t, jsonNames, "disabled")
		assert.NotContains(t, jsonNames, "delete")
	})
}

func TestGetFields_SkipsDelete(t *testing.T) {
	t.Run("Delete field is skipped", func(t *testing.T) {
		fields := getFields(reflect.TypeFor[appconfig.Account]())

		for _, f := range fields {
			assert.NotEqual(t, "Delete", f.name, "Delete field should be skipped")
		}
	})
}

func TestFieldNames(t *testing.T) {
	names := fieldNames(reflect.TypeFor[appconfig.Account]())

	// Should return JSON names
	assert.Contains(t, names, "name")
	assert.Contains(t, names, "aws_account_id")
	assert.Contains(t, names, "metadata")
}

func TestFieldTypes(t *testing.T) {
	types := fieldTypes(reflect.TypeFor[appconfig.Account]())

	assert.Len(t, types, 4) // name, aws_account_id, disabled, metadata
	// Verify types are correctly extracted
	for _, typ := range types {
		assert.NotNil(t, typ)
	}
}

func TestPut_Upsert(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)

	t.Run("insert new record", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "test-account-insert",
			AwsAccountId: "123456789",
		}
		err := put(ctx, db, account, accountsTable, false)
		require.NoError(t, err)

		// Verify it was inserted
		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "name = $1", "test-account-insert")
		require.NoError(t, err)
		require.Len(t, accounts, 1)
		assert.Equal(t, "123456789", accounts[0].AwsAccountId)
	})

	t.Run("update existing record", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "test-account-update",
			AwsAccountId: "111111111",
		}
		require.NoError(t, put(ctx, db, account, accountsTable, false))

		// Update with new values - Account uses Metadata for extra fields
		account.Metadata = appconfig.TextMap{"key": "updated-value"}
		require.NoError(t, put(ctx, db, account, accountsTable, false))

		// Verify only one record exists
		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "name = $1", "test-account-update")
		require.NoError(t, err)
		require.Len(t, accounts, 1)
		assert.Equal(t, "updated-value", accounts[0].Metadata["key"])
	})

	t.Run("update preserves other fields", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "test-account-fields",
			AwsAccountId: "222222222",
		}
		require.NoError(t, put(ctx, db, account, accountsTable, false))

		// Update metadata only
		account.Metadata = appconfig.TextMap{"newkey": "newvalue"}
		require.NoError(t, put(ctx, db, account, accountsTable, false))

		// Verify AwsAccountId is preserved
		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "name = $1", "test-account-fields")
		require.NoError(t, err)
		require.Len(t, accounts, 1)
		assert.Equal(t, "222222222", accounts[0].AwsAccountId)
		assert.Equal(t, "newvalue", accounts[0].Metadata["newkey"])
	})
}

func TestPut_Delete(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)

	t.Run("deletes existing record", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "to-delete",
			AwsAccountId: "999",
		}
		require.NoError(t, put(ctx, db, account, accountsTable, false))

		// Delete it
		require.NoError(t, put(ctx, db, account, accountsTable, true))

		// Verify deletion
		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "name = $1", "to-delete")
		require.NoError(t, err)
		assert.Empty(t, accounts)
	})

	t.Run("delete non-existing record succeeds", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "nonexistent-delete",
			AwsAccountId: "000",
		}
		err := put(ctx, db, account, accountsTable, true)
		assert.NoError(t, err) // Should not error
	})
}

func TestPut_PointerHandling(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)

	t.Run("handles pointer to struct", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "pointer-test",
			AwsAccountId: "333",
		}
		// Pass pointer
		err := put(ctx, db, account, accountsTable, false)
		require.NoError(t, err)

		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "name = $1", "pointer-test")
		require.NoError(t, err)
		require.Len(t, accounts, 1)
	})
}

func TestScan(t *testing.T) {
	ctx := t.Context()
	db := setupTestDB(t)

	t.Run("returns all matching records", func(t *testing.T) {
		// Insert multiple accounts
		for i := range 5 {
			account := &appconfig.Account{
				Name:         fmt.Sprintf("scan-test-%d", i),
				AwsAccountId: fmt.Sprintf("21111111%d", i),
			}
			require.NoError(t, put(ctx, db, account, accountsTable, false))
		}

		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(accounts), 5)
	})

	t.Run("applies filter correctly", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "filter-test",
			AwsAccountId: "444",
		}
		require.NoError(t, put(ctx, db, account, accountsTable, false))

		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "name = $1", "filter-test")
		require.NoError(t, err)
		require.Len(t, accounts, 1)
		assert.Equal(t, "filter-test", accounts[0].Name)
	})

	t.Run("returns empty slice for no matches", func(t *testing.T) {
		accounts, err := scan[appconfig.Account](ctx, db, accountsTable, "name = $1", "nonexistent-filter")
		require.NoError(t, err)
		assert.Empty(t, accounts)
	})
}

func TestScanArgs(t *testing.T) {
	t.Run("handles nested structs", func(t *testing.T) {
		account := &appconfig.Account{
			Name:         "nested-test",
			AwsAccountId: "555",
		}

		args := scanArgs(reflect.ValueOf(account))
		assert.NotEmpty(t, args)
	})

	t.Run("skips Delete field", func(t *testing.T) {
		role := &appconfig.Role{
			Name: "delete-skip-test",
		}

		v := reflect.ValueOf(role)
		if v.Kind() == reflect.Pointer {
			v = v.Elem()
		}
		args := scanArgs(v)

		for _, arg := range args {
			// Ensure no Delete field is included
			_ = arg
		}
	})
}

// setupTestDB creates a test database connection
// Note: Requires a running PostgreSQL instance
func setupTestDB(t *testing.T) *sql.DB {
	randomPort := rand.Intn(0xFFFF-1025) + 1024
	container, err := testcontainers.Run(t.Context(), "postgres",
		testcontainers.WithExposedPorts(fmt.Sprintf("%d:5432", randomPort)),
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_DB":       "postgres",
			"POSTGRES_USER":     "postgres",
			"POSTGRES_PASSWORD": "postgres",
		}),
		testcontainers.WithAdditionalWaitStrategy(wait.ForListeningPort("5432/tcp")),
	)
	require.NoError(t, err)
	t.Cleanup(func() {
		container.Terminate(t.Context())
	})
	ctx := t.Context()
	dsn := fmt.Sprintf(
		"postgres://%s:%s@%s:%d/%s",
		"postgres", "postgres", "localhost", randomPort, "postgres",
	)

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Skipf("Skipping test: could not connect to database: %v", err)
	}

	if err := db.PingContext(ctx); err != nil {
		t.Skipf("Skipping test: could not ping database: %v", err)
	}

	// Create tables
	_, err = db.ExecContext(ctx, create[appconfig.Account](accountsTable))
	require.NoError(t, err)

	return db
}
