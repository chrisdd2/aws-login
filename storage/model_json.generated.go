package storage

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

var (
	ErrRoleNotFound              = errors.New("Role does not exist")
	ErrRolePermissionNotFound    = errors.New("RolePermission does not exist")
	ErrAccountPermissionNotFound = errors.New("AccountPermission does not exist")
	ErrAccountNotFound           = errors.New("Account does not exist")
	ErrUserNotFound              = errors.New("User does not exist")
)

const (
	pageSize = 50
)

type Service interface {
	GetRole(ctx context.Context, id string) (*Role, error)
	GetRoles(ctx context.Context, id ...string) ([]*Role, error)
	ListRoles(ctx context.Context, accountId string, nextToken *string) (iter.Seq[*Role], *string, error)
	PutRole(ctx context.Context, role *Role, del bool) (*Role, error)
	ListRolePermissions(ctx context.Context, accountId string, userId string, nextToken *string) (iter.Seq[*RolePermission], *string, error)
	PutRolePermission(ctx context.Context, rolepermission *RolePermission, del bool) (*RolePermission, error)
	HasRolePermission(ctx context.Context, accountId string, userId string, roleId string, type_ RolePermissionType) (bool, error)
	ListAccountPermissions(ctx context.Context, accountId string, userId string, nextToken *string) (iter.Seq[*AccountPermission], *string, error)
	PutAccountPermission(ctx context.Context, accountpermission *AccountPermission, del bool) (*AccountPermission, error)
	HasAccountPermission(ctx context.Context, accountId string, userId string, type_ AccountPermissionType) (bool, error)

	GetAccount(ctx context.Context, id string) (*Account, error)
	GetAccounts(ctx context.Context, id ...string) ([]*Account, error)
	ListAccounts(ctx context.Context, nextToken *string) (iter.Seq[*Account], *string, error)
	PutAccount(ctx context.Context, account *Account, del bool) (*Account, error)
	GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (*Account, error)

	GetUser(ctx context.Context, id string) (*User, error)
	GetUsers(ctx context.Context, id ...string) ([]*User, error)
	ListUsers(ctx context.Context, nextToken *string) (iter.Seq[*User], *string, error)
	PutUser(ctx context.Context, user *User, del bool) (*User, error)
	GetUserByName(ctx context.Context, name string) (*User, error)

	Close() error
}

// Simple memory based implementation of the storage backend
//
// Persists data to a json file.
// Updates on every "write" action
//
// Performance is not great and not a priority
type JsonBackend struct {
	writeLock sync.Mutex
	fileName  string

	// fields to serialize to the actual file
	jsonSerializableFields
}

type jsonSerializableFields struct {
	LastUpdate         time.Time
	Roles              []*Role              `json:"roles,omitempty"`
	RolePermissions    []*RolePermission    `json:"rolepermissions,omitempty"`
	AccountPermissions []*AccountPermission `json:"accountpermissions,omitempty"`
	Accounts           []*Account           `json:"accounts,omitempty"`
	Users              []*User              `json:"users,omitempty"`
}

func NewJsonBackend(fileName string) (Service, error) {
	ret := &JsonBackend{
		fileName:               fileName,
		jsonSerializableFields: jsonSerializableFields{},
	}
	f, err := os.Open(fileName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ret, nil
		}
		return nil, err
	}
	defer f.Close()
	return ret, json.NewDecoder(f).Decode(&ret.jsonSerializableFields)
}

func (j *jsonSerializableFields) sortSlices() {
	j.Roles = slices.SortedFunc(slices.Values(j.Roles), func(u1, u2 *Role) int { return cmp.Compare(u1.Id, u2.Id) })
	j.RolePermissions = slices.SortedFunc(slices.Values(j.RolePermissions), func(u1, u2 *RolePermission) int { return cmp.Compare(u1.UserId, u2.UserId) })
	j.AccountPermissions = slices.SortedFunc(slices.Values(j.AccountPermissions), func(u1, u2 *AccountPermission) int { return cmp.Compare(u1.UserId, u2.UserId) })
	j.Accounts = slices.SortedFunc(slices.Values(j.Accounts), func(u1, u2 *Account) int { return cmp.Compare(u1.Id, u2.Id) })
	j.Users = slices.SortedFunc(slices.Values(j.Users), func(u1, u2 *User) int { return cmp.Compare(u1.Id, u2.Id) })
}

func (j *JsonBackend) lock() {
	j.writeLock.Lock()
}
func (j *JsonBackend) unlock() error {
	defer j.writeLock.Unlock()
	f, err := os.Create(j.fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	// make it readable
	j.sortSlices()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	j.LastUpdate = time.Now().UTC()
	return enc.Encode(j.jsonSerializableFields)
}

func (j *JsonBackend) Close() error {
	j.lock()
	// heh
	return j.unlock()
}

func parsePaginationToken(token *string, total int, pageSize int) (startPos, endPos int, nextToken *string, err error) {
	if token == nil {
		return 0, total, nil, nil
	}
	num, err := strconv.Atoi(*token)
	if err != nil {
		return -1, -1, nil, err
	}
	startPos = num
	endPos = num + pageSize
	if endPos > total {
		endPos = total
	} else {
		t := strconv.Itoa(endPos)
		nextToken = &t
	}
	return startPos, endPos, nextToken, nil
}

func matchOrEmpty(a, b string) bool {
	return b == "" || a == b
}

func (j *JsonBackend) GetRole(ctx context.Context, id string) (*Role, error) {
	for _, v := range j.Roles {
		if id == v.Id {
			return v, nil
		}
	}
	return nil, ErrRoleNotFound
}
func (j *JsonBackend) GetRoles(ctx context.Context, id ...string) ([]*Role, error) {
	ret := []*Role{}
	for _, v := range j.Roles {
		for _, z := range id {
			if z == v.Id {
				ret = append(ret, v)
				break
			}
		}
	}
	return ret, nil
}
func (j *JsonBackend) ListRoles(ctx context.Context, accountId string, nextToken *string) (iter.Seq[*Role], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.Roles), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*Role) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.Roles[i]
			if !(matchOrEmpty(accountId, item.AccountId)) {
				continue
			}

			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

func (j *JsonBackend) PutRole(ctx context.Context, role *Role, del bool) (*Role, error) {
	j.lock()
	defer j.unlock()
	if del {
		j.Roles = slices.DeleteFunc(j.Roles, func(v *Role) bool {
			return role.Id == v.Id
		})
		return role, nil
	}
	idx := slices.IndexFunc(j.Roles, func(v *Role) bool {
		return role.Id == v.Id
	})
	if idx != -1 {
		role.Id = j.Roles[idx].Id
		j.Roles[idx] = role
	} else {
		if role.Id == "" {
			role.Id = uuid.NewString()
		}
		j.Roles = append(j.Roles, role)
	}
	return role, nil
}

func (j *JsonBackend) ListRolePermissions(ctx context.Context, accountId string, userId string, nextToken *string) (iter.Seq[*RolePermission], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.RolePermissions), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*RolePermission) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.RolePermissions[i]
			if !(matchOrEmpty(accountId, item.AccountId) && matchOrEmpty(userId, item.UserId)) {
				continue
			}

			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

func (j *JsonBackend) PutRolePermission(ctx context.Context, rolepermission *RolePermission, del bool) (*RolePermission, error) {
	j.lock()
	defer j.unlock()
	if del {
		j.RolePermissions = slices.DeleteFunc(j.RolePermissions, func(v *RolePermission) bool {
			return rolepermission.AccountId == v.AccountId && rolepermission.UserId == v.UserId && rolepermission.RoleId == v.RoleId && rolepermission.Type == v.Type
		})
		return rolepermission, nil
	}
	idx := slices.IndexFunc(j.RolePermissions, func(v *RolePermission) bool {
		return rolepermission.AccountId == v.AccountId && rolepermission.UserId == v.UserId && rolepermission.RoleId == v.RoleId && rolepermission.Type == v.Type
	})
	if idx != -1 {
		rolepermission.UserId = j.RolePermissions[idx].UserId
		j.RolePermissions[idx] = rolepermission
	} else {
		if rolepermission.UserId == "" {
			rolepermission.UserId = uuid.NewString()
		}
		j.RolePermissions = append(j.RolePermissions, rolepermission)
	}
	return rolepermission, nil
}

func (j *JsonBackend) HasRolePermission(ctx context.Context, accountId string, userId string, roleId string, type_ RolePermissionType) (bool, error) {
	for _, v := range j.RolePermissions {
		if v.AccountId == accountId && v.UserId == userId && v.RoleId == roleId && v.Type == type_ {
			return true, nil
		}
	}
	return false, nil
}

func (j *JsonBackend) ListAccountPermissions(ctx context.Context, accountId string, userId string, nextToken *string) (iter.Seq[*AccountPermission], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.AccountPermissions), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*AccountPermission) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.AccountPermissions[i]
			if !(matchOrEmpty(accountId, item.AccountId) && matchOrEmpty(userId, item.UserId)) {
				continue
			}

			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

func (j *JsonBackend) PutAccountPermission(ctx context.Context, accountpermission *AccountPermission, del bool) (*AccountPermission, error) {
	j.lock()
	defer j.unlock()
	if del {
		j.AccountPermissions = slices.DeleteFunc(j.AccountPermissions, func(v *AccountPermission) bool {
			return accountpermission.AccountId == v.AccountId && accountpermission.UserId == v.UserId && accountpermission.Type == v.Type
		})
		return accountpermission, nil
	}
	idx := slices.IndexFunc(j.AccountPermissions, func(v *AccountPermission) bool {
		return accountpermission.AccountId == v.AccountId && accountpermission.UserId == v.UserId && accountpermission.Type == v.Type
	})
	if idx != -1 {
		accountpermission.UserId = j.AccountPermissions[idx].UserId
		j.AccountPermissions[idx] = accountpermission
	} else {
		if accountpermission.UserId == "" {
			accountpermission.UserId = uuid.NewString()
		}
		j.AccountPermissions = append(j.AccountPermissions, accountpermission)
	}
	return accountpermission, nil
}

func (j *JsonBackend) HasAccountPermission(ctx context.Context, accountId string, userId string, type_ AccountPermissionType) (bool, error) {
	for _, v := range j.AccountPermissions {
		if v.AccountId == accountId && v.UserId == userId && v.Type == type_ {
			return true, nil
		}
	}
	return false, nil
}

func (j *JsonBackend) GetAccount(ctx context.Context, id string) (*Account, error) {
	for _, v := range j.Accounts {
		if id == v.Id {
			return v, nil
		}
	}
	return nil, ErrAccountNotFound
}
func (j *JsonBackend) GetAccounts(ctx context.Context, id ...string) ([]*Account, error) {
	ret := []*Account{}
	for _, v := range j.Accounts {
		for _, z := range id {
			if z == v.Id {
				ret = append(ret, v)
				break
			}
		}
	}
	return ret, nil
}
func (j *JsonBackend) ListAccounts(ctx context.Context, nextToken *string) (iter.Seq[*Account], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.Accounts), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*Account) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.Accounts[i]
			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

func (j *JsonBackend) PutAccount(ctx context.Context, account *Account, del bool) (*Account, error) {
	j.lock()
	defer j.unlock()
	if del {
		j.Accounts = slices.DeleteFunc(j.Accounts, func(v *Account) bool {
			return account.AwsAccountId == v.AwsAccountId
		})
		return account, nil
	}
	idx := slices.IndexFunc(j.Accounts, func(v *Account) bool {
		return account.AwsAccountId == v.AwsAccountId
	})
	if idx != -1 {
		account.Id = j.Accounts[idx].Id
		j.Accounts[idx] = account
	} else {
		if account.Id == "" {
			account.Id = uuid.NewString()
		}
		j.Accounts = append(j.Accounts, account)
	}
	return account, nil
}

func (j *JsonBackend) GetAccountByAwsAccountId(ctx context.Context, awsAccountId int) (*Account, error) {
	for _, v := range j.Accounts {
		if v.AwsAccountId == awsAccountId {
			return v, nil
		}
	}
	return nil, ErrAccountNotFound
}

func (j *JsonBackend) GetUser(ctx context.Context, id string) (*User, error) {
	for _, v := range j.Users {
		if id == v.Id {
			return v, nil
		}
	}
	return nil, ErrUserNotFound
}
func (j *JsonBackend) GetUsers(ctx context.Context, id ...string) ([]*User, error) {
	ret := []*User{}
	for _, v := range j.Users {
		for _, z := range id {
			if z == v.Id {
				ret = append(ret, v)
				break
			}
		}
	}
	return ret, nil
}
func (j *JsonBackend) ListUsers(ctx context.Context, nextToken *string) (iter.Seq[*User], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.Users), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*User) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.Users[i]
			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

func (j *JsonBackend) PutUser(ctx context.Context, user *User, del bool) (*User, error) {
	j.lock()
	defer j.unlock()
	if del {
		j.Users = slices.DeleteFunc(j.Users, func(v *User) bool {
			return user.Name == v.Name
		})
		return user, nil
	}
	idx := slices.IndexFunc(j.Users, func(v *User) bool {
		return user.Name == v.Name
	})
	if idx != -1 {
		user.Id = j.Users[idx].Id
		j.Users[idx] = user
	} else {
		if user.Id == "" {
			user.Id = uuid.NewString()
		}
		j.Users = append(j.Users, user)
	}
	return user, nil
}

func (j *JsonBackend) GetUserByName(ctx context.Context, name string) (*User, error) {
	for _, v := range j.Users {
		if v.Name == name {
			return v, nil
		}
	}
	return nil, ErrUserNotFound
}
