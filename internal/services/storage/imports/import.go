package imports

import (
	"context"
	"fmt"

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

func ImportAll(ctx context.Context, st Importable, store *storage.InMemoryStore, del bool) ([]Change, error) {
	var changes []Change

	// Convert accounts to pointers
	accounts := make([]*appconfig.Account, len(store.Accounts))
	for i := range store.Accounts {
		accounts[i] = &store.Accounts[i]
	}

	// Import users
	userChanges, err := ImportUsers(ctx, st, store.Users, del)
	if err != nil {
		return nil, err
	}
	changes = append(changes, userChanges...)

	// Import accounts
	accountChanges, err := ImportAccounts(ctx, st, accounts, del)
	if err != nil {
		return nil, err
	}
	changes = append(changes, accountChanges...)

	// Import roles
	roleChanges, err := ImportRoles(ctx, st, store.Roles, del)
	if err != nil {
		return nil, err
	}
	changes = append(changes, roleChanges...)

	// Import policies
	policyChanges, err := ImportPolicies(ctx, st, store.Policies, del)
	if err != nil {
		return nil, err
	}
	changes = append(changes, policyChanges...)

	// Import role policy attachments
	rolePolicyChanges, err := ImportRolePolicyAttachments(ctx, st, store.RolePolicyAttachments, del)
	if err != nil {
		return nil, err
	}
	changes = append(changes, rolePolicyChanges...)

	// Import role account attachments
	roleAccountChanges, err := ImportRoleAccountAttachments(ctx, st, store.RoleAccountAttachments, del)
	if err != nil {
		return nil, err
	}
	changes = append(changes, roleAccountChanges...)

	// Import role user attachments
	roleUserChanges, err := ImportRoleUserAttachments(ctx, st, store.RoleUserAttachments, del)
	if err != nil {
		return nil, err
	}
	changes = append(changes, roleUserChanges...)

	return changes, nil
}

func ImportUsers(ctx context.Context, imp Importable, users []appconfig.User, del bool) ([]Change, error) {
	var changes []Change

	// Get existing users from storage
	existingUsers, err := imp.ListUsers(ctx)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, u := range existingUsers {
		existingSet[u] = true
	}

	// Track imported user names
	importedSet := make(map[string]bool)

	// Add/update users
	for i := range users {
		u := &users[i]
		if u.Delete {
			if err := imp.PutUser(ctx, u); err != nil {
				return nil, fmt.Errorf("delete user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeUser, Value: u.Name})
			continue
		}

		importedSet[u.Name] = true
		if existingSet[u.Name] {
			// Update existing user
			if err := imp.PutUser(ctx, u); err != nil {
				return nil, fmt.Errorf("update user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: ActionUpdate, ObjectType: ObjectTypeUser, Value: u.Name})
		} else {
			// Create new user
			if err := imp.PutUser(ctx, u); err != nil {
				return nil, fmt.Errorf("create user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: ActionCreate, ObjectType: ObjectTypeUser, Value: u.Name})
		}
	}

	// Delete users not in import (if del is true)
	if del {
		for _, name := range existingUsers {
			if !importedSet[name] {
				user := &appconfig.User{Name: name, CommonFields: appconfig.CommonFields{Delete: true}}
				if err := imp.PutUser(ctx, user); err != nil {
					return nil, fmt.Errorf("delete user %s: %w", name, err)
				}
				changes = append(changes, Change{Action: "delete", ObjectType: "user", Value: name})
			}
		}
	}

	return changes, nil
}

func ImportAccounts(ctx context.Context, imp Importable, accounts []*appconfig.Account, del bool) ([]Change, error) {
	var changes []Change

	// Get existing accounts from storage
	existingAccounts, err := imp.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, a := range existingAccounts {
		existingSet[a.Name] = true
	}

	// Track imported account names
	importedSet := make(map[string]bool)

	// Add/update accounts
	for i := range accounts {
		a := accounts[i]
		if a.Delete {
			if err := imp.PutAccount(ctx, a); err != nil {
				return nil, fmt.Errorf("delete account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeAccount, Value: a.Name})
			continue
		}

		importedSet[a.Name] = true
		if existingSet[a.Name] {
			if err := imp.PutAccount(ctx, a); err != nil {
				return nil, fmt.Errorf("update account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: ActionUpdate, ObjectType: ObjectTypeAccount, Value: a.Name})
		} else {
			if err := imp.PutAccount(ctx, a); err != nil {
				return nil, fmt.Errorf("create account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: ActionCreate, ObjectType: ObjectTypeAccount, Value: a.Name})
		}
	}

	// Delete accounts not in import
	if del {
		for _, a := range existingAccounts {
			if !importedSet[a.Name] {
				account := &appconfig.Account{Name: a.Name, CommonFields: appconfig.CommonFields{Delete: true}}
				if err := imp.PutAccount(ctx, account); err != nil {
					return nil, fmt.Errorf("delete account %s: %w", a.Name, err)
				}
				changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeAccount, Value: a.Name})
			}
		}
	}

	return changes, nil
}

func ImportRoles(ctx context.Context, imp Importable, roles []appconfig.Role, del bool) ([]Change, error) {
	var changes []Change

	// Get existing roles from storage
	existingRoles, err := imp.ListRoles(ctx)
	if err != nil {
		return nil, fmt.Errorf("list roles: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, r := range existingRoles {
		existingSet[r] = true
	}

	// Track imported role names
	importedSet := make(map[string]bool)

	// Add/update roles
	for i := range roles {
		r := &roles[i]
		if r.Delete {
			if err := imp.PutRole(ctx, r); err != nil {
				return nil, fmt.Errorf("delete role %s: %w", r.Name, err)
			}
			changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRole, Value: r.Name})
			continue
		}

		importedSet[r.Name] = true
		if existingSet[r.Name] {
			if err := imp.PutRole(ctx, r); err != nil {
				return nil, fmt.Errorf("update role %s: %w", r.Name, err)
			}
			changes = append(changes, Change{Action: ActionUpdate, ObjectType: ObjectTypeRole, Value: r.Name})
		} else {
			if err := imp.PutRole(ctx, r); err != nil {
				return nil, fmt.Errorf("create role %s: %w", r.Name, err)
			}
			changes = append(changes, Change{Action: ActionCreate, ObjectType: ObjectTypeRole, Value: r.Name})
		}
	}

	// Delete roles not in import
	if del {
		for _, name := range existingRoles {
			if !importedSet[name] {
				role := &appconfig.Role{Name: name, CommonFields: appconfig.CommonFields{Delete: true}}
				if err := imp.PutRole(ctx, role); err != nil {
					return nil, fmt.Errorf("delete role %s: %w", name, err)
				}
				changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRole, Value: name})
			}
		}
	}

	return changes, nil
}

func ImportPolicies(ctx context.Context, imp Importable, policies []appconfig.Policy, del bool) ([]Change, error) {
	var changes []Change

	// Get existing policies
	existingPolicies, err := imp.ListPolicies(ctx)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, p := range existingPolicies {
		existingSet[p] = true
	}

	importedSet := make(map[string]bool)

	// Add/update policies
	for i := range policies {
		p := &policies[i]

		if err := imp.PutPolicy(ctx, p); err != nil {
			return nil, fmt.Errorf("put policy %s: %w", p.Id, err)
		}

		changes = append(changes, Change{
			Action:     action(p.Delete, existingSet[p.Id]),
			ObjectType: ObjectTypePolicy,
			Value:      p.Id})
		importedSet[p.Id] = true
	}

	// Delete policies not in import
	if del {
		for _, p := range existingPolicies {
			if !importedSet[p] {
				policy := &appconfig.Policy{Id: p, CommonFields: appconfig.CommonFields{Delete: true}}
				if err := imp.PutPolicy(ctx, policy); err != nil {
					return nil, fmt.Errorf("delete policy %s: %w", p, err)
				}
				changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypePolicy, Value: p})
			}
		}
	}

	return changes, nil
}

func roleUserAttachmentKey(at appconfig.RoleUserAttachment) string {
	return at.Username + "|" + at.RoleName + "|" + at.AccountName
}

func rolePolicyAttachmentKey(at appconfig.RolePolicyAttachment) string {
	return at.RoleName + "|" + at.PolicyId
}

func roleAccountAttachmentKey(at appconfig.RoleAccountAttachment) string {
	return at.RoleName + "|" + at.AccountName
}

func ImportRoleUserAttachments(ctx context.Context, imp Importable, attachments []appconfig.RoleUserAttachment, del bool) ([]Change, error) {
	var changes []Change

	// Get existing attachments from storage
	existingAttachments, err := imp.ListRoleUserAttachments(ctx, "", "", "")
	if err != nil {
		return nil, fmt.Errorf("list role user attachments: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, at := range existingAttachments {
		existingSet[roleUserAttachmentKey(at)] = true
	}

	// Track imported attachment keys
	importedSet := make(map[string]bool)

	// Add/update attachments
	for i := range attachments {
		at := &attachments[i]
		if at.Delete {
			if err := imp.PutRoleUserAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("delete role user attachment %s: %w", roleUserAttachmentKey(*at), err)
			}
			changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRoleUserAttachment, Value: roleUserAttachmentKey(*at)})
			continue
		}

		key := roleUserAttachmentKey(*at)
		importedSet[key] = true
		if existingSet[key] {
			if err := imp.PutRoleUserAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("update role user attachment %s: %w", key, err)
			}
			changes = append(changes, Change{Action: ActionUpdate, ObjectType: ObjectTypeRoleUserAttachment, Value: key})
		} else {
			if err := imp.PutRoleUserAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("create role user attachment %s: %w", key, err)
			}
			changes = append(changes, Change{Action: ActionCreate, ObjectType: ObjectTypeRoleUserAttachment, Value: key})
		}
	}

	// Delete attachments not in import
	if del {
		for _, at := range existingAttachments {
			key := roleUserAttachmentKey(at)
			if !importedSet[key] {
				attachment := &appconfig.RoleUserAttachment{
					RoleUserAttachmentId: at.RoleUserAttachmentId,
					CommonFields:         appconfig.CommonFields{Delete: true}}
				if err := imp.PutRoleUserAttachment(ctx, attachment); err != nil {
					return nil, fmt.Errorf("delete role user attachment %s: %w", key, err)
				}
				changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRoleUserAttachment, Value: key})
			}
		}
	}

	return changes, nil
}

func ImportRolePolicyAttachments(ctx context.Context, imp Importable, attachments []appconfig.RolePolicyAttachment, del bool) ([]Change, error) {
	var changes []Change

	// Get existing attachments from storage
	existingAttachments, err := imp.ListRolePolicyAttachments(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("list role policy attachments: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, at := range existingAttachments {
		existingSet[rolePolicyAttachmentKey(at)] = true
	}

	// Track imported attachment keys
	importedSet := make(map[string]bool)

	// Add/update attachments
	for i := range attachments {
		at := &attachments[i]
		if at.Delete {
			if err := imp.PutRolePolicyAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("delete role policy attachment %s: %w", rolePolicyAttachmentKey(*at), err)
			}
			changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRolePolicyAttachment, Value: rolePolicyAttachmentKey(*at)})
			continue
		}

		key := rolePolicyAttachmentKey(*at)
		importedSet[key] = true
		if existingSet[key] {
			if err := imp.PutRolePolicyAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("update role policy attachment %s: %w", key, err)
			}
			changes = append(changes, Change{Action: ActionUpdate, ObjectType: ObjectTypeRolePolicyAttachment, Value: key})
		} else {
			if err := imp.PutRolePolicyAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("create role policy attachment %s: %w", key, err)
			}
			changes = append(changes, Change{Action: ActionCreate, ObjectType: ObjectTypeRolePolicyAttachment, Value: key})
		}
	}

	// Delete attachments not in import
	if del {
		for _, at := range existingAttachments {
			key := rolePolicyAttachmentKey(at)
			if !importedSet[key] {
				attachment := &appconfig.RolePolicyAttachment{RoleName: at.RoleName, PolicyId: at.PolicyId, CommonFields: appconfig.CommonFields{Delete: true}}
				if err := imp.PutRolePolicyAttachment(ctx, attachment); err != nil {
					return nil, fmt.Errorf("delete role policy attachment %s: %w", key, err)
				}
				changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRolePolicyAttachment, Value: key})
			}
		}
	}

	return changes, nil
}

func ImportRoleAccountAttachments(ctx context.Context, imp Importable, attachments []appconfig.RoleAccountAttachment, del bool) ([]Change, error) {
	var changes []Change

	// Get existing attachments from storage
	existingAttachments, err := imp.ListRoleAccountAttachments(ctx, "", "")
	if err != nil {
		return nil, fmt.Errorf("list role account attachments: %w", err)
	}
	existingSet := make(map[string]bool)
	for _, at := range existingAttachments {
		existingSet[roleAccountAttachmentKey(at)] = true
	}

	// Track imported attachment keys
	importedSet := make(map[string]bool)

	// Add/update attachments
	for i := range attachments {
		at := &attachments[i]
		if at.Delete {
			if err := imp.PutRoleAccountAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("delete role account attachment %s: %w", roleAccountAttachmentKey(*at), err)
			}
			changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRoleAccountAttachment, Value: roleAccountAttachmentKey(*at)})
			continue
		}

		key := roleAccountAttachmentKey(*at)
		importedSet[key] = true
		if existingSet[key] {
			if err := imp.PutRoleAccountAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("update role account attachment %s: %w", key, err)
			}
			changes = append(changes, Change{Action: ActionUpdate, ObjectType: ObjectTypeRoleAccountAttachment, Value: key})
		} else {
			if err := imp.PutRoleAccountAttachment(ctx, at); err != nil {
				return nil, fmt.Errorf("create role account attachment %s: %w", key, err)
			}
			changes = append(changes, Change{Action: ActionCreate, ObjectType: ObjectTypeRoleAccountAttachment, Value: key})
		}
	}

	// Delete attachments not in import
	if del {
		for _, at := range existingAttachments {
			key := roleAccountAttachmentKey(at)
			if !importedSet[key] {
				attachment := &appconfig.RoleAccountAttachment{RoleName: at.RoleName, AccountName: at.AccountName, CommonFields: appconfig.CommonFields{Delete: true}}
				if err := imp.PutRoleAccountAttachment(ctx, attachment); err != nil {
					return nil, fmt.Errorf("delete role account attachment %s: %w", key, err)
				}
				changes = append(changes, Change{Action: ActionDelete, ObjectType: ObjectTypeRoleAccountAttachment, Value: key})
			}
		}
	}

	return changes, nil
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
