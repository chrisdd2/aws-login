package imports

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"reflect"
	"strings"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services/storage"
)

const (
	ActionCreate = "create"
	ActionUpdate = "update"
	ActionDelete = "delete"

	ObjectTypeUser                  = "user"
	ObjectTypeAccount               = "account"
	ObjectTypeRole                  = "role"
	ObjectTypePolicy                = "policy"
	ObjectTypeRoleUserAttachment    = "role_user_attachment"
	ObjectTypeRolePolicyAttachment  = "role_policy_attachment"
	ObjectTypeRoleAccountAttachment = "role_account_attachment"
)

type Change struct {
	Action     string
	ObjectType string
	Value      string
}

type Importable interface {
	storage.Writeable
	storage.Readable
}

func importItems[T any](ctx context.Context, imp importer[T], items iter.Seq[T], del bool) ([]Change, error) {
	var changes []Change

	objectType := imp.ObjectType()

	// Get existing accounts from storage
	existing, err := imp.Existing(ctx)
	if err != nil {
		return nil, fmt.Errorf("imp.Existing: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, a := range existing {
		existingSet[a] = true
	}

	// Track imported
	importedSet := make(map[string]bool)

	// Add/update users
	for item := range items {
		name := imp.Id(item)

		importedSet[name] = true
		if imp.ShouldDelete(item) {
			if err := imp.Put(ctx, item, true); err != nil {
				return nil, fmt.Errorf("delete %s: %w", name, err)
			}
			changes = append(changes, Change{Action: ActionDelete, ObjectType: objectType, Value: name})
			continue
		}

		existed := existingSet[name]
		if existed {
			i, err := imp.Item(ctx, name)
			if err != nil {
				return nil, fmt.Errorf("get item %s: %w", name, err)
			}
			if reflect.DeepEqual(i, item) {
				continue
			}
			if err := imp.Put(ctx, item, false); err != nil {
				return nil, fmt.Errorf("update %s: %w", name, err)
			}
			changes = append(changes, Change{Action: ActionUpdate, ObjectType: objectType, Value: name})
		} else {
			// Create new item
			if err := imp.Put(ctx, item, false); err != nil {
				return nil, fmt.Errorf("create %s: %w", name, err)
			}
			changes = append(changes, Change{Action: ActionCreate, ObjectType: objectType, Value: name})
		}
	}

	// Delete users not in import (if del is true)
	if del {
		for _, name := range existing {
			if !importedSet[name] {
				item, err := imp.Item(ctx, name)
				if err != nil {
					return nil, fmt.Errorf("imp.Item %s: %w", name, err)
				}
				if err := imp.Put(ctx, item, true); err != nil {
					return nil, fmt.Errorf("delete item %s: %w", name, err)
				}
				changes = append(changes, Change{Action: "delete", ObjectType: objectType, Value: name})
			}
		}
	}

	return changes, nil

}

func refIter[T any](ar []T) iter.Seq[*T] {
	return func(yield func(*T) bool) {
		for _, v := range ar {
			if !yield(&v) {
				break
			}
		}
	}
}

type accum struct {
	changes []Change
	err     error
}

func (a *accum) Run(c []Change, err error) {
	a.changes = append(a.changes, c...)
	a.err = errors.Join(a.err, err)
}

func ImportAll(ctx context.Context, st Importable, store *storage.InMemoryStore, del bool) ([]Change, error) {
	ret := accum{}
	ret.Run(importItems(ctx, userImporter{st}, refIter(store.Users), del))
	ret.Run(importItems(ctx, roleImporter{st}, refIter(store.Roles), del))
	ret.Run(importItems(ctx, accountImporter{st}, refIter(store.Accounts), del))
	ret.Run(importItems(ctx, policyImporter{st}, refIter(store.Policies), del))
	ret.Run(importItems(ctx, roleAccountAttachmentImporter{st}, refIter(store.RoleAccountAttachments), del))
	ret.Run(importItems(ctx, roleUserAttachmentImporter{st}, refIter(store.RoleUserAttachments), del))
	ret.Run(importItems(ctx, rolePolicyAttachmentImporter{st}, refIter(store.RolePolicyAttachments), del))
	return ret.changes, ret.err
}

func ImportPermissions(ctx context.Context, st Importable, users []appconfig.User, permissions []appconfig.RoleUserAttachment, del bool) ([]Change, error) {
	ret := accum{}

	ret.Run(importItems(ctx, userImporter{st}, refIter(users), del))
	ret.Run(importItems(ctx, roleUserAttachmentImporter{st}, refIter(permissions), del))
	return ret.changes, ret.err
}

func action(del bool, exists bool) string {
	if del {
		return ActionDelete
	}
	if exists {
		return ActionUpdate
	}
	return ActionCreate
}

// code of shame, this is just because go is go

type importer[T any] interface {
	Id(a T) string
	Item(ctx context.Context, id string) (T, error)
	Existing(ctx context.Context) ([]string, error)
	Put(ctx context.Context, a T, del bool) error
	ShouldDelete(a T) bool
	ObjectType() string
}

var (
	_userImporter        importer[*appconfig.User]                  = userImporter{nil}
	_roleImporter        importer[*appconfig.Role]                  = roleImporter{nil}
	_accountImporter     importer[*appconfig.Account]               = accountImporter{nil}
	_policyImporter      importer[*appconfig.Policy]                = policyImporter{nil}
	_roleAccountImporter importer[*appconfig.RoleAccountAttachment] = roleAccountAttachmentImporter{nil}
	_roleUserImporter    importer[*appconfig.RoleUserAttachment]    = roleUserAttachmentImporter{nil}
	_rolePolicyImporter  importer[*appconfig.RolePolicyAttachment]  = rolePolicyAttachmentImporter{nil}
)

type userImporter struct{ s Importable }

func (u userImporter) Id(a *appconfig.User) string {
	return a.Name
}

func (u userImporter) Item(ctx context.Context, id string) (*appconfig.User, error) {
	return u.s.GetUser(ctx, id)
}
func (u userImporter) Existing(ctx context.Context) ([]string, error) {
	return u.s.ListUsers(ctx)
}
func (u userImporter) Put(ctx context.Context, usr *appconfig.User, del bool) error {
	usr.Delete = del
	return u.s.PutUser(ctx, usr)
}
func (u userImporter) ShouldDelete(a *appconfig.User) bool {
	return a.Delete
}
func (u userImporter) ObjectType() string {
	return ObjectTypeUser
}

type roleImporter struct{ s Importable }

func (u roleImporter) Id(a *appconfig.Role) string {
	return a.Name
}

func (u roleImporter) Item(ctx context.Context, id string) (*appconfig.Role, error) {
	return u.s.GetRole(ctx, id)
}
func (u roleImporter) Existing(ctx context.Context) ([]string, error) {
	return u.s.ListRoles(ctx)
}
func (u roleImporter) Put(ctx context.Context, usr *appconfig.Role, del bool) error {
	usr.Delete = del
	return u.s.PutRole(ctx, usr)
}
func (u roleImporter) ShouldDelete(a *appconfig.Role) bool {
	return a.Delete
}
func (u roleImporter) ObjectType() string {
	return ObjectTypeRole
}

type accountImporter struct{ s Importable }

func (u accountImporter) Id(a *appconfig.Account) string {
	return a.Name
}

func (u accountImporter) Item(ctx context.Context, id string) (*appconfig.Account, error) {
	return u.s.GetAccount(ctx, id)
}
func (u accountImporter) Existing(ctx context.Context) ([]string, error) {
	accs, err := u.s.ListAccounts(ctx)
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, v := range accs {
		ret = append(ret, v.Name)
	}
	return ret, nil
}
func (u accountImporter) Put(ctx context.Context, usr *appconfig.Account, del bool) error {
	usr.Delete = del
	return u.s.PutAccount(ctx, usr)
}
func (u accountImporter) ShouldDelete(a *appconfig.Account) bool {
	return a.Delete
}
func (u accountImporter) ObjectType() string {
	return ObjectTypeAccount
}

type policyImporter struct{ s Importable }

func (u policyImporter) Id(a *appconfig.Policy) string {
	return a.Id
}

func (u policyImporter) Item(ctx context.Context, id string) (*appconfig.Policy, error) {
	return u.s.GetPolicy(ctx, id)
}
func (u policyImporter) Existing(ctx context.Context) ([]string, error) {
	return u.s.ListPolicies(ctx)
}
func (u policyImporter) Put(ctx context.Context, usr *appconfig.Policy, del bool) error {
	usr.Delete = del
	return u.s.PutPolicy(ctx, usr)
}
func (u policyImporter) ShouldDelete(a *appconfig.Policy) bool {
	return a.Delete
}
func (u policyImporter) ObjectType() string {
	return ObjectTypePolicy
}

type roleAccountAttachmentImporter struct{ s Importable }

func (u roleAccountAttachmentImporter) Id(v *appconfig.RoleAccountAttachment) string {
	return strings.Join([]string{v.RoleName, v.AccountName}, "|")
}

func (u roleAccountAttachmentImporter) Item(ctx context.Context, id string) (*appconfig.RoleAccountAttachment, error) {
	parts := strings.Split(id, "|")
	if len(parts) < 2 {
		return nil, errors.New("invalid id argument")
	}
	at, err := u.s.ListRoleAccountAttachments(ctx, parts[0], parts[1])
	if err != nil {
		return nil, err
	}
	if len(at) < 1 {
		return nil, storage.ErrAttachmentNotFound
	}
	return &at[0], err
}
func (u roleAccountAttachmentImporter) Existing(ctx context.Context) ([]string, error) {
	accs, err := u.s.ListRoleAccountAttachments(ctx, "", "")
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, v := range accs {
		ret = append(ret, strings.Join([]string{v.RoleName, v.AccountName}, "|"))
	}
	return ret, nil
}
func (u roleAccountAttachmentImporter) Put(ctx context.Context, usr *appconfig.RoleAccountAttachment, del bool) error {
	usr.Delete = del
	return u.s.PutRoleAccountAttachment(ctx, usr)
}
func (u roleAccountAttachmentImporter) ShouldDelete(a *appconfig.RoleAccountAttachment) bool {
	return a.Delete
}
func (u roleAccountAttachmentImporter) ObjectType() string {
	return ObjectTypeRoleAccountAttachment
}

type roleUserAttachmentImporter struct{ s Importable }

func (u roleUserAttachmentImporter) Id(v *appconfig.RoleUserAttachment) string {
	return strings.Join([]string{v.Username, v.RoleName, v.AccountName}, "|")
}

func (u roleUserAttachmentImporter) Item(ctx context.Context, id string) (*appconfig.RoleUserAttachment, error) {
	parts := strings.Split(id, "|")
	if len(parts) < 3 {
		return nil, errors.New("invalid id argument")
	}
	at, err := u.s.ListRoleUserAttachments(ctx, parts[0], parts[1], parts[2])
	if err != nil {
		return nil, err
	}
	if len(at) < 1 {
		return nil, storage.ErrAttachmentNotFound
	}
	return &at[0], err
}
func (u roleUserAttachmentImporter) Existing(ctx context.Context) ([]string, error) {
	accs, err := u.s.ListRoleUserAttachments(ctx, "", "", "")
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, v := range accs {
		ret = append(ret, u.Id(&v))
	}
	return ret, nil
}
func (u roleUserAttachmentImporter) Put(ctx context.Context, usr *appconfig.RoleUserAttachment, del bool) error {
	usr.Delete = del
	return u.s.PutRoleUserAttachment(ctx, usr)
}
func (u roleUserAttachmentImporter) ShouldDelete(a *appconfig.RoleUserAttachment) bool {
	return a.Delete
}
func (u roleUserAttachmentImporter) ObjectType() string {
	return ObjectTypeRoleUserAttachment
}

type rolePolicyAttachmentImporter struct{ s Importable }

func (u rolePolicyAttachmentImporter) Id(v *appconfig.RolePolicyAttachment) string {
	return strings.Join([]string{v.RoleName, v.PolicyId}, "|")
}

func (u rolePolicyAttachmentImporter) Item(ctx context.Context, id string) (*appconfig.RolePolicyAttachment, error) {
	parts := strings.Split(id, "|")
	policyId := parts[1]
	if len(parts) < 2 {
		return nil, errors.New("invalid id argument")
	}
	ats, err := u.s.ListRolePolicyAttachments(ctx, parts[0])
	if err != nil {
		return nil, err
	}
	for _, at := range ats {
		if at.PolicyId == policyId {
			return &at, nil
		}
	}
	return nil, storage.ErrAttachmentNotFound
}
func (u rolePolicyAttachmentImporter) Existing(ctx context.Context) ([]string, error) {
	accs, err := u.s.ListRolePolicyAttachments(ctx, "")
	if err != nil {
		return nil, err
	}
	ret := []string{}
	for _, v := range accs {
		ret = append(ret, strings.Join([]string{v.RoleName, v.PolicyId}, "|"))
	}
	return ret, nil
}
func (u rolePolicyAttachmentImporter) Put(ctx context.Context, usr *appconfig.RolePolicyAttachment, del bool) error {
	usr.Delete = del
	return u.s.PutRolePolicyAttachment(ctx, usr)
}
func (u rolePolicyAttachmentImporter) ShouldDelete(a *appconfig.RolePolicyAttachment) bool {
	return a.Delete
}
func (u rolePolicyAttachmentImporter) ObjectType() string {
	return ObjectTypeRolePolicyAttachment
}
