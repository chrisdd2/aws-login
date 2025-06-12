package storage

import (
	"context"
	"encoding/json"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
)

type MemoryStorage struct {
	users     []User
	accounts  []Account
	perms     []Permission
	flushFunc FlushFunc
	flushLock sync.Mutex
}

type FlushFunc func(*MemoryStorage)

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		users:    []User{},
		accounts: []Account{},
		perms:    []Permission{},
	}
}

type jsonMemorystore struct {
	Users    []User       `json:"users,omitempty"`
	Accounts []Account    `json:"accounts,omitempty"`
	Perms    []Permission `json:"perms,omitempty"`
}

func (m *MemoryStorage) LoadFromReader(reader io.Reader) error {
	store := jsonMemorystore{}
	err := json.NewDecoder(reader).Decode(&store)
	if err != nil {
		return err
	}
	m.users = store.Users
	m.accounts = store.Accounts
	m.perms = store.Perms
	return nil
}

func (m *MemoryStorage) SaveToWriter(writer io.Writer) error {
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

func (m *MemoryStorage) SetFlush(f FlushFunc) {
	m.flushFunc = f
}

func (m *MemoryStorage) Flush() {
	if m.flushFunc != nil {
		m.flushLock.Lock()
		m.flushFunc(m)
		m.flushLock.Unlock()
	}
}

func (m *MemoryStorage) ListUsers(ctx context.Context, filter string, startToken *string) (ListUserResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListUserResult{}, err
	}
	users := make([]User, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx >= len(m.users) {
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

func (m *MemoryStorage) ListPermissions(ctx context.Context, userId string, accountId string, permissionType string, scope string, startToken *string) (ListPermissionResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListPermissionResult{}, err
	}
	perms := make([]Permission, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx > len(m.perms) {
		endIdx = len(m.perms)
		startToken = nil
	}
	for i := startIdx; i < endIdx; i++ {
		perm := m.perms[i]
		if !(matchOrEmpty(perm.UserId, userId) && matchOrEmpty(perm.AccountId, accountId) && matchOrEmpty(perm.Scope, scope) && matchOrEmpty(perm.Type, permissionType)) {
			continue
		}
		perms = append(perms, perm)
	}
	return ListPermissionResult{Permissions: perms, StartToken: startToken}, nil
}

func (m *MemoryStorage) ListAccounts(ctx context.Context, startToken *string) (ListAccountResult, error) {
	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListAccountResult{}, err
	}
	accounts := make([]Account, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx >= len(m.accounts) {
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
		return false
	}

	startIdx, err := parseStartToken(startToken)
	if err != nil {
		return ListAccountResult{}, err
	}

	accounts := make([]Account, 0, ListResultPageSize)
	endIdx := startIdx + ListResultPageSize
	startToken = generateStartToken(endIdx)
	if endIdx >= len(m.accounts) {
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
func (m *MemoryStorage) BatchGetUserById(ctx context.Context, userId ...string) ([]User, error) {
	users := []User{}
	for _, user := range m.users {
		if slices.Contains(userId, user.Id) {
			users = append(users, user)
		}
	}
	return users, nil
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

func (m *MemoryStorage) GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (Account, error) {
	if awsAccountId == 0 {
		return Account{}, ErrAccountNotFound
	}
	for _, acc := range m.accounts {
		if acc.AwsAccountId == awsAccountId {
			return acc, nil
		}
	}
	return Account{}, ErrAccountNotFound
}

func (m *MemoryStorage) PutAccount(ctx context.Context, account Account, delete bool) (Account, error) {
	defer m.Flush()
	if delete {
		m.accounts = slices.DeleteFunc(m.accounts, func(a Account) bool {
			return a.Id == account.Id
		})
		return account, nil
	}
	for i, acc := range m.accounts {
		if acc.AwsAccountId == account.AwsAccountId && acc.AwsAccountId != 0 {
			account.Id = acc.Id
			m.accounts[i] = account
			// exists
			return account, nil
		}
	}
	if account.Id == "" {
		account.Id = newUuid()
		m.accounts = append(m.accounts, account)
	}
	return account, nil
}
func (m *MemoryStorage) PutUser(ctx context.Context, usr User, delete bool) (User, error) {
	defer m.Flush()
	if delete {
		m.users = slices.DeleteFunc(m.users, func(a User) bool {
			return a.Id == usr.Id
		})
		return usr, nil
	}
	for i, user := range m.users {
		if user.Id == usr.Id {
			user.Superuser = usr.Superuser
			m.users[i] = user
			return user, nil
		}
	}
	usr.Id = newUuid()
	m.users = append(m.users, usr)
	return usr, nil
}
func (m *MemoryStorage) PutRolePermission(ctx context.Context, newPerm Permission, delete bool) error {
	defer m.Flush()
	if delete {
		m.perms = slices.DeleteFunc(m.perms, func(a Permission) bool {
			return a.PermissionId == newPerm.PermissionId
		})
		return nil
	}
	for i, perm := range m.perms {
		if perm.PermissionId == newPerm.PermissionId {
			// exists
			m.perms[i] = newPerm
			return nil
		}
	}
	m.perms = append(m.perms, newPerm)
	return nil
}

func matchOrEmpty(item string, check string) bool {
	return item == check || check == ""
}
func newUuid() string {
	return strings.ReplaceAll(uuid.NewString(), "-", "")
}
