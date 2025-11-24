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

// Simple memory based implementation of the storage backend
//
// Persists data to a json file.
// Updates on every "write" action
//
// Performance is not great and not a priority
type jsonBackend struct {
	writeLock sync.Mutex
	fileName  string

	// fields to serialize to the actual file
	jsonSerializableFields
}

type jsonSerializableFields struct {
	LastUpdate         time.Time            `json:"last_update,omitempty"`
	Users              []*User              `json:"users,omitempty"`
	Accounts           []*Account           `json:"accounts,omitempty"`
	AccountPermissions []*AccountPermission `json:"account_permissions,omitempty"`
	Roles              []*Role              `json:"roles,omitempty"`
	RolePermissions    []*RolePermission    `json:"role_permissions,omitempty"`
}

func NewJsonBackend(fileName string) (Service, error) {
	ret := &jsonBackend{
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
	j.Users = slices.SortedFunc(slices.Values(j.Users), func(u1, u2 *User) int { return cmp.Compare(u1.Id, u1.Id) })
	j.Accounts = slices.SortedFunc(slices.Values(j.Accounts), func(u1, u2 *Account) int { return cmp.Compare(u1.Id, u1.Id) })
	j.Roles = slices.SortedFunc(slices.Values(j.Roles), func(u1, u2 *Role) int { return cmp.Compare(u1.Id, u1.Id) })
	j.AccountPermissions = slices.SortedFunc(slices.Values(j.AccountPermissions), func(u1, u2 *AccountPermission) int {
		return cmp.Compare(u1.UserId, u1.UserId)
	})
	j.RolePermissions = slices.SortedFunc(slices.Values(j.RolePermissions), func(u1, u2 *RolePermission) int { return cmp.Compare(u1.UserId, u1.UserId) })
}

func (j *jsonBackend) lock() {
	j.writeLock.Lock()
}
func (j *jsonBackend) unlock() error {
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

func (j *jsonBackend) Close() error {
	j.lock()
	// heh
	return j.unlock()
}

func (j *jsonBackend) GetUsers(ctx context.Context, id ...string) ([]*User, error) {
	ret := []*User{}
	for _, usr := range j.Users {
		if slices.Contains(id, usr.Id) {
			ret = append(ret, usr)
		}
	}
	return ret, nil
}

func (j *jsonBackend) GetUserByName(ctx context.Context, name string) (*User, error) {
	for _, usr := range j.Users {
		if usr.Name == name {
			return usr, nil
		}
	}
	return nil, ErrUserNotFound
}
func (j *jsonBackend) PutUser(ctx context.Context, user *User, del bool) (*User, error) {
	j.lock()
	defer j.unlock()
	if del && user.Id != "" {
		j.Users = slices.DeleteFunc(j.Users, func(u *User) bool {
			return user.Id == u.Id
		})
		return user, nil
	}
	idx := slices.IndexFunc(j.Users, func(u *User) bool {
		return user.Name == u.Name
	})
	if idx != -1 {
		user.Id = j.Users[idx].Id
	} else {
		// new user
		if user.Id == "" {
			user.Id = uuid.NewString()
		}
	}
	j.Users = append(j.Users, user)
	return user, nil
}
func (j *jsonBackend) ListUsers(ctx context.Context, nextToken *string) (iter.Seq[*User], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.Roles), pageSize)
	if err != nil {
		return nil, nil, err
	}
	// there is no order on the map so just yolo it
	return func(yield func(*User) bool) {
		for i := startPos; i < endPos; i++ {
			if !yield(j.Users[i]) {
				break
			}
		}
	}, nextToken, nil
}

func (j *jsonBackend) GetAccount(ctx context.Context, id ...string) ([]*Account, error) {
	ret := []*Account{}
	for _, acc := range j.Accounts {
		if slices.Contains(id, acc.Id) {
			ret = append(ret, acc)
		}
	}
	return ret, nil

}

func (j *jsonBackend) GetAccountByAwsAccountId(ctx context.Context, accountId int) (*Account, error) {
	for _, acc := range j.Accounts {
		if acc.AwsAccountId == accountId {
			return acc, nil
		}
	}
	return nil, ErrAccountNotFound

}
func (j *jsonBackend) PutAccount(ctx context.Context, account *Account, del bool) (*Account, error) {
	j.lock()
	defer j.unlock()
	if del && account.Id != "" {
		j.Accounts = slices.DeleteFunc(j.Accounts, func(acc *Account) bool {
			return acc.Id == account.Id
		})
		return account, nil
	}
	idx := slices.IndexFunc(j.Accounts, func(acc *Account) bool {
		return acc.AwsAccountId == account.AwsAccountId
	})
	if idx != -1 {
		account.Id = j.Accounts[idx].Id
	} else if account.Id == "" {
		account.Id = uuid.NewString()
	}
	j.Accounts = append(j.Accounts, account)
	return account, nil
}

const pageSize = 50

func (j *jsonBackend) ListAccounts(ctx context.Context, nextToken *string) (iter.Seq[*Account], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.Roles), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*Account) bool) {
		for i := startPos; i < endPos; i++ {
			if !yield(j.Accounts[i]) {
				break
			}

		}
	}, nextToken, nil
}

func (j *jsonBackend) PutAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType, delete bool) error {
	j.lock()
	defer j.unlock()
	idx := slices.IndexFunc(j.AccountPermissions, func(perm *AccountPermission) bool {
		return perm.AccountId == accountId && perm.Type == permissionType && perm.UserId == userId
	})
	if idx == -1 {
		j.AccountPermissions = append(j.AccountPermissions, &AccountPermission{
			AccountId: accountId,
			UserId:    userId,
			Type:      permissionType,
		})
	}
	return nil
}
func (j *jsonBackend) HasAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType) (bool, error) {
	return slices.ContainsFunc(j.AccountPermissions, func(perm *AccountPermission) bool {
		return perm.AccountId == accountId && perm.Type == permissionType && perm.UserId == userId
	}), nil
}
func (j *jsonBackend) ListAccountPermissions(ctx context.Context, userId string, accountId string, nextToken *string) (iter.Seq[*AccountPermission], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.AccountPermissions), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*AccountPermission) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.AccountPermissions[i]
			if !(matchOrEmpty(item.UserId, userId) && matchOrEmpty(item.AccountId, accountId)) {
				continue
			}
			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

func (j *jsonBackend) PutRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType, del bool) (*RolePermission, error) {
	j.lock()
	defer j.unlock()

	if del {
		j.RolePermissions = slices.DeleteFunc(j.RolePermissions, func(perm *RolePermission) bool {
			return perm.AccountId == accountId && perm.UserId == userId && perm.RoleId == roleId && perm.Type == permissionType
		})
		return nil, nil
	}
	idx := slices.IndexFunc(j.RolePermissions, func(perm *RolePermission) bool {
		return perm.AccountId == accountId && perm.UserId == userId && perm.RoleId == roleId && perm.Type == permissionType
	})
	if idx == -1 {
		perm := &RolePermission{
			UserId:    userId,
			AccountId: accountId,
			Type:      permissionType,
			RoleId:    roleId,
		}
		j.RolePermissions = append(j.RolePermissions, perm)
		return perm, nil
	}
	return j.RolePermissions[idx], nil
}
func (j *jsonBackend) HasRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType) (bool, error) {
	return slices.ContainsFunc(j.RolePermissions, func(perm *RolePermission) bool {
		return perm.AccountId == accountId && perm.UserId == userId && perm.RoleId == roleId && perm.Type == permissionType
	}), nil
}
func (j *jsonBackend) ListRolePermissions(ctx context.Context, userId string, accountId string, nextToken *string) (iter.Seq[*RolePermission], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.AccountPermissions), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*RolePermission) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.RolePermissions[i]
			if !(matchOrEmpty(item.UserId, userId) && matchOrEmpty(item.AccountId, accountId)) {
				continue
			}
			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

func (j *jsonBackend) GetRole(ctx context.Context, id ...string) ([]*Role, error) {
	ret := make([]*Role, 0, len(id))
	for _, i := range id {
		idx := slices.IndexFunc(j.Roles, func(role *Role) bool { return role.Id == i })
		if idx == -1 {
			continue
		}
		ret = append(ret, j.Roles[idx])
	}
	return ret, nil
}
func (j *jsonBackend) PutRole(ctx context.Context, role *Role, del bool) (*Role, error) {
	j.lock()
	defer j.unlock()

	if del {
		j.Roles = slices.DeleteFunc(j.Roles, func(item *Role) bool {
			return item.Name == role.Name || item.Id == role.Id
		})
		return nil, nil
	}
	idx := slices.IndexFunc(j.Roles, func(item *Role) bool {
		return item.Name == role.Name || item.Id == role.Id
	})
	if idx == -1 {
		j.Roles = append(j.Roles, role)
		return role, nil
	}
	return j.Roles[idx], nil
}
func (j *jsonBackend) ListRoles(ctx context.Context, accountId string, nextToken *string) (iter.Seq[*Role], *string, error) {
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.AccountPermissions), pageSize)
	if err != nil {
		return nil, nil, err
	}
	if accountId == "" {
		return func(yield func(*Role) bool) {
			for i := startPos; i < endPos; i++ {
				if !yield(j.Roles[i]) {
					break
				}
			}
		}, nextToken, nil
	}
	return func(yield func(*Role) bool) {
		for i := startPos; i < endPos; i++ {
			role := j.Roles[i]
			if role.AccountId != accountId {
				continue
			}
			if !yield(role) {
				break
			}
		}
	}, nextToken, nil
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
