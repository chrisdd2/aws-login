package storage

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type MemoryStorage struct {
	users    []User
	accounts []Account
	perms    []UserPermission
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		users:    []User{},
		accounts: []Account{},
		perms:    []UserPermission{},
	}
}

type jsonMemorystore struct {
	Users    []User           `json:"users,omitempty"`
	Accounts []Account        `json:"accounts,omitempty"`
	Perms    []UserPermission `json:"perms,omitempty"`
}

func NewMemoryStorageFromJson(reader io.Reader) (*MemoryStorage, error) {
	store := jsonMemorystore{}
	err := json.NewDecoder(reader).Decode(&store)
	if err != nil {
		return nil, err
	}
	return &MemoryStorage{store.Users, store.Accounts, store.Perms}, nil

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

const ListResultPageSize = 50

func parseStartToken(token *string) (int, error) {
	if token == nil {
		return 0, nil
	}
	num, err := strconv.Atoi(*token)
	if err != nil {
		return 0, err
	}
	return num, nil
}
func generateStartToken(num int) *string {
	k := strconv.Itoa(num)
	return &k
}

func (m *MemoryStorage) ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListUserResult{}, err
	}
	users := make([]User, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx > len(m.users) {
		endIdx = len(m.users)
		startToken = nil
	}
	for i := startIdx; i < endIdx; i++ {
		if !(filter == "" || strings.HasPrefix(m.users[i].Username, filter)) {
			continue
		}
		users = append(users, m.users[i])
	}
	return ListUserResult{Users: users, StartToken: startToken}, nil
}

func (m *MemoryStorage) ListUserPermissions(ctx context.Context, userId string, accountId string, scope string, startToken *string) (ListUserPermissionResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListUserPermissionResult{}, err
	}
	perms := make([]UserPermission, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx > len(m.perms) {
		endIdx = len(m.perms)
		startToken = nil
	}
	for i := startIdx; i < endIdx; i++ {
		perm := m.perms[i]
		if !(matchOrEmpty(perm.UserId, userId) && matchOrEmpty(perm.AccountId, accountId) && matchOrEmpty(perm.Scope, scope)) {
			continue
		}
		perms = append(perms, perm)
	}
	return ListUserPermissionResult{UserPermissions: perms, StartToken: startToken}, nil
}

func (m *MemoryStorage) ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListAccountResult{}, err
	}
	accounts := make([]Account, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx > len(m.accounts) {
		endIdx = len(m.accounts)
		startToken = nil
	}
	for i := startIdx; i < endIdx; i++ {
		accounts = append(accounts, m.accounts[i])
	}
	return ListAccountResult{Accounts: accounts, StartToken: startToken}, nil
}
func (m *MemoryStorage) ListAccountsForUser(ctx context.Context, userId string, startToken *string) (ListAccountResult, error) {
	// this is somewhat slow
	hasPermForAccount := func(accountId string) bool {
		for _, perm := range m.perms {
			if perm.UserId == userId && perm.AccountId == accountId {
				return true
			}
		}
		return true
	}

	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListAccountResult{}, err
	}
	accounts := make([]Account, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx > len(m.accounts) {
		endIdx = len(m.accounts)
		startToken = nil
	}
	for i := startIdx; i < endIdx; i++ {
		account := m.accounts[i]
		if hasPermForAccount(account.Id) {
			accounts = append(accounts, account)
		}
	}
	return ListAccountResult{Accounts: accounts, StartToken: startToken}, nil
}
func (m *MemoryStorage) GetUserByUsername(ctx context.Context, username string) (User, error) {
	if username == "" {
		return User{}, ErrUserNotFound
	}
	for _, user := range m.users {
		if user.Username == username {
			return user, nil
		}
	}
	return User{}, ErrUserNotFound
}

func (m *MemoryStorage) GetUserById(ctx context.Context, userId string) (User, error) {
	if userId == "" {
		return User{}, ErrUserNotFound
	}
	for _, user := range m.users {
		if user.Id == userId {
			return user, nil
		}
	}
	return User{}, ErrUserNotFound
}
func (m *MemoryStorage) GetAccountById(ctx context.Context, accountId string) (Account, error) {
	if accountId == "" {
		return Account{}, ErrAccountNotFound
	}
	for _, acc := range m.accounts {
		if acc.Id == accountId {
			return acc, nil
		}
	}
	return Account{}, ErrAccountNotFound
}

func (m *MemoryStorage) PutAccount(ctx context.Context, account Account) (Account, error) {
	for i, acc := range m.accounts {
		if acc.AwsAccountId == acc.AwsAccountId {
			account.Id = acc.Id
			m.accounts[i] = account
			// exists
			break
		}
	}
	if account.Id == "" {
		account.Id = uuid.New().String()
	}
	m.accounts = append(m.accounts, account)
	return account, nil
}
func (m *MemoryStorage) PutUser(ctx context.Context, usr User) (User, error) {
	_, err := m.GetUserByUsername(ctx, usr.Username)
	if err == ErrUserNotFound {
		usr.Id = uuid.New().String()
	}
	m.users = append(m.users, usr)
	return usr, nil
}
func (m *MemoryStorage) PutUserPermission(ctx context.Context, newPerm UserPermission) error {
	for i, perm := range m.perms {
		if perm.UserPermissionId == newPerm.UserPermissionId {
			// exists
			perm.Value = append(perm.Value, newPerm.Value...)
			m.perms[i] = perm
			break
		}
	}
	m.perms = append(m.perms, newPerm)
	return nil
}
func (m *MemoryStorage) DeleteUser(ctx context.Context, userId string) error {
	m.users = slices.DeleteFunc(m.users, func(a User) bool {
		return a.Id == userId
	})
	return nil
}

func matchOrEmpty(item string, check string) bool {
	return item == check || check == ""
}
