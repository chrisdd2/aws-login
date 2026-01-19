package services

import (
	"context"
	"testing"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services/storage"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenService_Create(t *testing.T) {
	ctx := context.Background()
	key := []byte("test-secret-key-32-bytes-long!!")

	t.Run("creates token with default expiration", func(t *testing.T) {
		mockStorage := &MockStorage{}
		svc := NewToken(mockStorage, key)

		user := &UserInfo{
			Username:     "testuser",
			FriendlyName: "Test User",
			Superuser:    false,
			LoginType:    "github",
		}

		token, err := svc.Create(ctx, user, false)
		require.NoError(t, err)
		assert.NotEmpty(t, token)

		// Validate the token
		claims, err := svc.Validate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, "testuser", claims.Username)
		assert.Equal(t, "Test User", claims.FriendlyName)
		assert.False(t, claims.Superuser)
		assert.Equal(t, "github", claims.LoginType)
	})

	t.Run("validates superuser flag from storage", func(t *testing.T) {
		mockStorage := &MockStorage{
			users: map[string]*appconfig.User{
				"admin": {Superuser: true},
				"user":  {Superuser: false},
			},
		}
		svc := NewToken(mockStorage, key)

		tests := []struct {
			name     string
			username string
			want     bool
		}{
			{"admin is superuser", "admin", true},
			{"regular user is not superuser", "user", false},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				user := &UserInfo{Username: tt.username}
				token, err := svc.Create(ctx, user, true)
				require.NoError(t, err)

				claims, err := svc.Validate(ctx, token)
				require.NoError(t, err)
				assert.Equal(t, tt.want, claims.Superuser)
			})
		}
	})

	t.Run("preserves IdpToken in claims", func(t *testing.T) {
		mockStorage := &MockStorage{}
		svc := NewToken(mockStorage, key)

		idpToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
		user := &UserInfo{
			Username: "testuser",
			IdpToken: idpToken,
		}

		token, err := svc.Create(ctx, user, false)
		require.NoError(t, err)

		claims, err := svc.Validate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, idpToken, claims.IdpToken)
	})

	t.Run("returns error when user not found in storage during validation", func(t *testing.T) {
		mockStorage := &MockStorage{
			users: map[string]*appconfig.User{},
		}
		svc := NewToken(mockStorage, key)

		user := &UserInfo{Username: "nonexistent"}
		_, err := svc.Create(ctx, user, true)
		assert.ErrorIs(t, err, storage.ErrUserNotFound)
	})
}

func TestTokenService_Validate(t *testing.T) {
	ctx := context.Background()
	key := []byte("test-secret-key-32-bytes-long!!")
	wrongKey := []byte("wrong-secret-key-32-bytes!!")

	t.Run("rejects expired token", func(t *testing.T) {
		svc := NewToken(&MockStorage{}, key)

		// Create an expired token manually
		claims := UserClaims{
			UserInfo: UserInfo{Username: "test"},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString(key)
		require.NoError(t, err)

		_, err = svc.Validate(ctx, tokenStr)
		assert.Error(t, err)
	})

	t.Run("rejects token signed with wrong key", func(t *testing.T) {
		svc := NewToken(&MockStorage{}, key)

		claims := UserClaims{
			UserInfo: UserInfo{Username: "test"},
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenStr, err := token.SignedString(wrongKey)
		require.NoError(t, err)

		_, err = svc.Validate(ctx, tokenStr)
		assert.Error(t, err)
	})

	t.Run("rejects malformed token", func(t *testing.T) {
		svc := NewToken(&MockStorage{}, key)

		_, err := svc.Validate(ctx, "not.a.valid.token")
		assert.Error(t, err)
	})

	t.Run("rejects empty token", func(t *testing.T) {
		svc := NewToken(&MockStorage{}, key)

		_, err := svc.Validate(ctx, "")
		assert.Error(t, err)
	})

	t.Run("extracts all user info fields from claims", func(t *testing.T) {
		svc := NewToken(&MockStorage{}, key)

		user := &UserInfo{
			Username:     "fulluser",
			FriendlyName: "Full User Name",
			Superuser:    true,
			LoginType:    "google",
			IdpToken:     "test-token",
		}

		token, err := svc.Create(ctx, user, false)
		require.NoError(t, err)

		claims, err := svc.Validate(ctx, token)
		require.NoError(t, err)

		assert.Equal(t, "fulluser", claims.Username)
		assert.Equal(t, "Full User Name", claims.FriendlyName)
		assert.True(t, claims.Superuser)
		assert.Equal(t, "google", claims.LoginType)
		assert.Equal(t, "test-token", claims.IdpToken)
	})
}

func TestTokenService_SuperuserOverride(t *testing.T) {
	ctx := context.Background()
	key := []byte("test-secret-key-32-bytes-long!!")

	t.Run("validate=false preserves original superuser flag", func(t *testing.T) {
		mockStorage := &MockStorage{
			users: map[string]*appconfig.User{
				"admin": {Superuser: true},
			},
		}
		svc := NewToken(mockStorage, key)

		// Even though storage says admin=true, we pass validate=false
		// so the flag should be preserved from the input
		user := &UserInfo{
			Username:  "admin",
			Superuser: false, // Input says not superuser
		}

		token, err := svc.Create(ctx, user, false)
		require.NoError(t, err)

		claims, err := svc.Validate(ctx, token)
		require.NoError(t, err)
		assert.False(t, claims.Superuser)
	})

	t.Run("validate=true overrides with storage value", func(t *testing.T) {
		mockStorage := &MockStorage{
			users: map[string]*appconfig.User{
				"admin": {Superuser: true},
			},
		}
		svc := NewToken(mockStorage, key)

		user := &UserInfo{
			Username:  "admin",
			Superuser: false, // Input says not superuser
		}

		token, err := svc.Create(ctx, user, true)
		require.NoError(t, err)

		claims, err := svc.Validate(ctx, token)
		require.NoError(t, err)
		assert.True(t, claims.Superuser)
	})
}

// MockStorage implements storage.Readable for testing
type MockStorage struct {
	users map[string]*appconfig.User
}

func (m *MockStorage) Reload(ctx context.Context) error {
	return nil
}

func (m *MockStorage) Display(ctx context.Context) (*storage.InMemoryStore, error) {
	return &storage.InMemoryStore{}, nil
}

func (m *MockStorage) Import(ctx context.Context, st *storage.InMemoryStore) error {
	return nil
}

func (m *MockStorage) GetUser(ctx context.Context, username string) (*appconfig.User, error) {
	if u, ok := m.users[username]; ok {
		return u, nil
	}
	return nil, storage.ErrUserNotFound
}

func (m *MockStorage) ListUsers(ctx context.Context) ([]string, error) {
	users := make([]string, 0, len(m.users))
	for u := range m.users {
		users = append(users, u)
	}
	return users, nil
}

// Unused methods - satisfy the interface with panics
func (m *MockStorage) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	panic("not implemented")
}

func (m *MockStorage) GetAccount(ctx context.Context, id string) (*appconfig.Account, error) {
	panic("not implemented")
}

func (m *MockStorage) GetPolicy(ctx context.Context, id string) (*appconfig.Policy, error) {
	panic("not implemented")
}

func (m *MockStorage) ListAccounts(ctx context.Context) ([]appconfig.Account, error) {
	panic("not implemented")
}

func (m *MockStorage) ListPolicies(ctx context.Context) ([]string, error) {
	panic("not implemented")
}

func (m *MockStorage) ListRoles(ctx context.Context) ([]string, error) {
	panic("not implemented")
}

func (m *MockStorage) ListRoleAccountAttachments(ctx context.Context, roleName, accountName string) ([]appconfig.RoleAccountAttachment, error) {
	panic("not implemented")
}

func (m *MockStorage) ListRoleUserAttachments(ctx context.Context, username, roleName, accountName string) ([]appconfig.RoleUserAttachment, error) {
	panic("not implemented")
}

func (m *MockStorage) ListRolePolicyAttachments(ctx context.Context, roleName string) ([]appconfig.RolePolicyAttachment, error) {
	panic("not implemented")
}

func (m *MockStorage) ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error) {
	panic("not implemented")
}

func (m *MockStorage) ListRolePermissions(ctx context.Context, userName, roleName, accountName string) ([]appconfig.RoleUserAttachment, error) {
	panic("not implemented")
}
