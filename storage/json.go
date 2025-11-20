package storage

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"os"
	"slices"
	"strings"
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

type userIdKey string
type accountIdKey string
type roleIdKey string

type jsonSerializableFields struct {
	LastUpdate         time.Time                             `json:"last_update,omitempty"`
	Users              map[userIdKey]*User                   `json:"users,omitempty"`
	Accounts           map[accountIdKey]*Account             `json:"accounts,omitempty"`
	AccountPermissions map[accountIdKey][]*AccountPermission `json:"account_permissions,omitempty"`
	Roles              map[roleIdKey]*Role                   `json:"roles,omitempty"`
	RolePermissions    map[userIdKey][]*RolePermission       `json:"role_permissions,omitempty"`
}

func NewJsonBackend(fileName string) (StorageBackend, error) {
	ret := &jsonBackend{
		fileName: fileName,
		jsonSerializableFields: jsonSerializableFields{
			// nil map is menace
			Users:              map[userIdKey]*User{},
			Accounts:           map[accountIdKey]*Account{},
			Roles:              map[roleIdKey]*Role{},
			AccountPermissions: map[accountIdKey][]*AccountPermission{},
			RolePermissions:    map[userIdKey][]*RolePermission{},
		},
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
		delete(j.Users, userIdKey(user.Id))
		return user, nil
	}
	existingUsr, exists := j.Users[userIdKey(user.Id)]
	if exists {
		user.Id = existingUsr.Id
	} else {
		// new user
		if user.Id == "" {
			user.Id = uuid.NewString()
		}
	}
	j.Users[userIdKey(user.Id)] = user
	return user, nil
}
func (j *jsonBackend) ListUsers(ctx context.Context, prefix string) (iter.Seq[*User], error) {
	// there is no order on the map so just yolo it
	return func(yield func(*User) bool) {
		for _, v := range j.Users {
			if prefix == "" || strings.HasPrefix(v.Name, prefix) {
				if !yield(v) {
					break
				}
			}
		}
	}, nil
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
func (j *jsonBackend) PutAccount(ctx context.Context, acc *Account, del bool) (*Account, error) {
	j.lock()
	defer j.unlock()
	if del && acc.Id != "" {
		delete(j.Accounts, accountIdKey(acc.Id))
		return acc, nil
	}
	existingAcc, exists := j.Accounts[accountIdKey(acc.Id)]
	if exists {
		// already exists just update but make sure to keep the existing id
		acc.Id = existingAcc.Id
	} else if acc.Id == "" {
		acc.Id = uuid.NewString()
	}
	j.Accounts[accountIdKey(acc.Id)] = acc
	return acc, nil
}

const pageSize = 50

func (j *jsonBackend) ListAccounts(ctx context.Context) (iter.Seq[*Account], error) {
	return func(yield func(*Account) bool) {
		for _, v := range j.Accounts {
			if !yield(v) {
				break
			}
		}
	}, nil
}

func (j *jsonBackend) PutAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType, delete bool) error {
	j.lock()
	defer j.unlock()

	accPerms := j.AccountPermissions[accountIdKey(accountId)]
	matcher := func(perm *AccountPermission) bool {
		return perm.UserId == userId && permissionType == perm.Type
	}
	if delete {
		j.AccountPermissions[accountIdKey(accountId)] = slices.DeleteFunc(accPerms, matcher)
	}
	if slices.ContainsFunc(accPerms, matcher) {
		return nil
	}
	perm := &AccountPermission{
		AccountId: accountId,
		UserId:    userId,
		Type:      permissionType,
	}
	j.AccountPermissions[accountIdKey(accountId)] = append(accPerms, perm)
	return nil
}
func (j *jsonBackend) HasAccountPermission(ctx context.Context, userId string, accountId string, permissionType AccountPermissionType) (bool, error) {
	usr := j.Users[userIdKey(userId)]
	if usr.Superuser {
		return true, nil
	}
	accPerms := j.AccountPermissions[accountIdKey(accountId)]
	return slices.ContainsFunc(accPerms, func(perm *AccountPermission) bool {
		return perm.UserId == userId && permissionType == perm.Type
	}), nil
}
func (j *jsonBackend) ListAccountPermissions(ctx context.Context, userId string, accountId string) (iter.Seq[*AccountPermission], error) {
	accPerms := j.AccountPermissions[accountIdKey(accountId)]
	if userId == "" {
		return func(yield func(*AccountPermission) bool) {
			for _, perm := range accPerms {
				if !yield(perm) {
					break
				}
			}
		}, nil
	}
	return func(yield func(*AccountPermission) bool) {
		for _, perm := range accPerms {
			if perm.UserId != userId {
				continue
			}
			if !yield(perm) {
				break
			}
		}
	}, nil
}

func (j *jsonBackend) PutRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType, delete bool) (*RolePermission, error) {
	j.lock()
	defer j.unlock()

	userPerms := j.RolePermissions[userIdKey(userId)]
	matcher := func(
		perm *RolePermission,
	) bool {
		return perm.UserId == userId && accountId == perm.AccountId && roleId == perm.RoleId && permissionType == perm.Type
	}
	if delete {
		j.RolePermissions[userIdKey(userId)] = slices.DeleteFunc(userPerms, matcher)
		return nil, nil
	}
	idx := slices.IndexFunc(userPerms, matcher)
	if idx != -1 {
		return userPerms[idx], nil
	}
	perm := RolePermission{
		UserId:    userId,
		AccountId: accountId,
		Type:      permissionType,
		RoleId:    roleId,
	}
	j.RolePermissions[userIdKey(userId)] = append(userPerms, &perm)
	return &perm, nil
}
func (j *jsonBackend) HasRolePermission(ctx context.Context, userId string, accountId string, roleId string, permissionType RolePermissionType) (bool, error) {
	usr := j.Users[userIdKey(userId)]
	if usr.Superuser {
		return true, nil
	}
	userPerms := j.RolePermissions[userIdKey(userId)]
	return slices.ContainsFunc(userPerms, func(perm *RolePermission) bool {
		return perm.UserId == userId && accountId == perm.AccountId && roleId == perm.RoleId && permissionType == perm.Type
	}), nil
}
func (j *jsonBackend) ListRolePermissions(ctx context.Context, userId string, accountId string) (iter.Seq[*RolePermission], error) {
	userPerms := j.RolePermissions[userIdKey(userId)]
	if accountId == "" {
		return func(yield func(*RolePermission) bool) {
			for _, perm := range userPerms {
				if !yield(perm) {
					break
				}
			}
		}, nil
	}
	return func(yield func(*RolePermission) bool) {
		for _, perm := range userPerms {
			if perm.AccountId != accountId {
				continue
			}
			if !yield(perm) {
				break
			}
		}
	}, nil
}

func (j *jsonBackend) GetRole(ctx context.Context, id ...string) ([]*Role, error) {
	ret := make([]*Role, 0, len(id))
	for _, i := range id {
		role, ok := j.Roles[roleIdKey(i)]
		if !ok {
			return nil, ErrRoleNotFound
		}
		ret = append(ret, role)
	}
	return ret, nil
}
func (j *jsonBackend) PutRole(ctx context.Context, role *Role, del bool) (*Role, error) {
	j.lock()
	defer j.unlock()
	// find existing
	for id, r := range j.Roles {
		if r.AccountId == role.AccountId && r.Name == role.Name {
			if del {
				delete(j.Roles, id)
				return nil, nil
			}
			// found overwrite existing
			role.Id = string(id)
			j.Roles[id] = role
			return role, nil
		}
	}
	role.Id = uuid.NewString()
	j.Roles[roleIdKey(role.Id)] = role
	return role, nil
}
func (j *jsonBackend) ListRoles(ctx context.Context, accountId string) (iter.Seq[*Role], error) {
	if accountId == "" {
		return func(yield func(*Role) bool) {
			for _, role := range j.Roles {
				if !yield(role) {
					break
				}
			}
		}, nil
	}
	return func(yield func(*Role) bool) {
		for _, role := range j.Roles {
			if role.AccountId == accountId {
			}
		}
	}, nil
}
