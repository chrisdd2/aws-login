package storage

import (
	"context"
	"encoding/json"
	"io"
	"strings"

	"github.com/google/uuid"
)

type MemoryStorage struct {
	users    map[string]User
	accounts map[string]Account
	perms    map[UserPermissionId]UserPermission
}

func NewMemoryStorage() MemoryStorage {
	return MemoryStorage{
		users:    map[string]User{},
		accounts: map[string]Account{},
		perms:    map[UserPermissionId]UserPermission{},
	}
}

type jsonMemorystore struct {
	Users    map[string]User                     `json:"users,omitempty"`
	Accounts map[string]Account                  `json:"accounts,omitempty"`
	Perms    map[UserPermissionId]UserPermission `json:"perms,omitempty"`
}

func NewMemoryStorageFromJson(reader io.Reader) (*MemoryStorage, error) {
	store := jsonMemorystore{}
	err := json.NewDecoder(reader).Decode(&store)
	if err != nil {
		return nil, err
	}
	return &MemoryStorage{
		users:    store.Users,
		accounts: store.Accounts,
		perms:    store.Perms,
	}, nil
}
func SaveMemoryStorageFromJson(m *MemoryStorage, writer io.Writer) error {
	store := jsonMemorystore{
		Users:    m.users,
		Accounts: m.accounts,
		Perms:    m.perms,
	}
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	return enc.Encode(&store)
}

func (m *MemoryStorage) ListUsers(ctx context.Context, filter string) UserIter {
	return func(yield func(User, error) bool) {
		for _, user := range m.users {
			if !(filter == "" || strings.HasPrefix(user.Label, filter)) {
				continue
			}
			if !yield(user, nil) {
				return
			}
		}
	}
}
func (m *MemoryStorage) ListUserPermissions(ctx context.Context, userId string) UserPermissionIter {
	return func(yield func(UserPermission, error) bool) {
		for _, perm := range m.perms {
			if !(userId == "" || perm.UserId == userId) {
				continue
			}
			if !yield(perm, nil) {
				return
			}
		}
	}
}
func (m *MemoryStorage) ListAccounts(ctx context.Context) AccountIter {
	return func(yield func(Account, error) bool) {
		for _, acc := range m.accounts {
			if !yield(acc, nil) {
				return
			}
		}
	}
}
func (m *MemoryStorage) ListAccountsForUser(ctx context.Context, userId string) AccountIter {
	return func(yield func(Account, error) bool) {
		accounts := map[string]struct{}{}
		for _, perm := range m.perms {
			if !(perm.UserId == userId) {
				continue
			}
			accounts[perm.AccountId] = struct{}{}
		}
		for acc := range accounts {
			if !yield(m.accounts[acc], nil) {
				return
			}
		}
	}
}
func (m *MemoryStorage) GetUserByEmail(ctx context.Context, email string) (User, error) {
	for _, user := range m.users {
		if user.Email == email {
			return user, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (m *MemoryStorage) PutAccount(ctx context.Context, account Account) (Account, error) {
	for _, acc := range m.accounts {
		if acc.AwsAccountId == acc.AwsAccountId {
			account.Id = acc.Id
			break
		}
	}
	if account.Id == "" {
		account.Id = uuid.New().String()
	}
	m.accounts[account.Id] = account
	return account, nil
}
func (m *MemoryStorage) PutUser(ctx context.Context, usr User) (User, error) {
	_, err := m.GetUserByEmail(ctx, usr.Email)
	if err == ErrUserNotFound {
		usr.Id = uuid.New().String()
	}
	m.users[usr.Id] = usr
	return usr, nil
}
func (m *MemoryStorage) PutUserPermission(ctx context.Context, perm UserPermission) error {
	m.perms[perm.UserPermissionId] = perm
	return nil
}
func (m *MemoryStorage) DeleteUserBy(ctx context.Context, email string) error {
	usr, err := m.GetUserByEmail(ctx, email)
	if err == ErrUserNotFound {
		return nil
	}
	return m.DeleteUser(ctx, usr.Id)
}
func (m *MemoryStorage) DeleteUser(ctx context.Context, userId string) error {
	delete(m.users, userId)
	return nil
}
