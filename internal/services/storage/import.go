package storage

import (
	"context"
	"fmt"

	"github.com/chrisdd2/aws-login/appconfig"
)

type Change struct {
	Action     string
	ObjectType string
	Value      string
}

type Importable interface {
	Writeable
	Readable
}

func ImportAll(ctx context.Context, st Importable, store *InMemoryStore, del bool) ([]Change, error) {
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
		if u.DeleteMarker.Delete {
			if err := imp.PutUser(ctx, u, true); err != nil {
				return nil, fmt.Errorf("delete user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: "delete", ObjectType: "user", Value: u.Name})
			continue
		}

		importedSet[u.Name] = true
		if existingSet[u.Name] {
			// Update existing user
			if err := imp.PutUser(ctx, u, false); err != nil {
				return nil, fmt.Errorf("update user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: "update", ObjectType: "user", Value: u.Name})
		} else {
			// Create new user
			if err := imp.PutUser(ctx, u, false); err != nil {
				return nil, fmt.Errorf("create user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: "create", ObjectType: "user", Value: u.Name})
		}
	}

	// Delete users not in import (if del is true)
	if del {
		for _, name := range existingUsers {
			if !importedSet[name] {
				user := &appconfig.User{Name: name, DeleteMarker: appconfig.DeleteMarker{Delete: true}}
				if err := imp.PutUser(ctx, user, true); err != nil {
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
		if a.DeleteMarker.Delete {
			if err := imp.PutAccount(ctx, a, true); err != nil {
				return nil, fmt.Errorf("delete account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: "delete", ObjectType: "account", Value: a.Name})
			continue
		}

		importedSet[a.Name] = true
		if existingSet[a.Name] {
			if err := imp.PutAccount(ctx, a, false); err != nil {
				return nil, fmt.Errorf("update account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: "update", ObjectType: "account", Value: a.Name})
		} else {
			if err := imp.PutAccount(ctx, a, false); err != nil {
				return nil, fmt.Errorf("create account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: "create", ObjectType: "account", Value: a.Name})
		}
	}

	// Delete accounts not in import
	if del {
		for _, a := range existingAccounts {
			if !importedSet[a.Name] {
				account := &appconfig.Account{Name: a.Name, DeleteMarker: appconfig.DeleteMarker{Delete: true}}
				if err := imp.PutAccount(ctx, account, true); err != nil {
					return nil, fmt.Errorf("delete account %s: %w", a.Name, err)
				}
				changes = append(changes, Change{Action: "delete", ObjectType: "account", Value: a.Name})
			}
		}
	}

	return changes, nil
}

func ImportRoles(ctx context.Context, imp Importable, roles []appconfig.Role, del bool) ([]Change, error) {
	var changes []Change

	// Get existing roles by listing accounts and their roles
	accounts, err := imp.ListAccounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("list accounts: %w", err)
	}

	existingRoles := make(map[string]bool)
	for _, a := range accounts {
		accountRoles, err := imp.ListRolesForAccount(ctx, a.Name)
		if err != nil {
			return nil, fmt.Errorf("list roles for account %s: %w", a.Name, err)
		}
		for _, r := range accountRoles {
			existingRoles[r.Name] = true
		}
	}

	importedSet := make(map[string]bool)

	// Add/update roles
	for i := range roles {
		r := &roles[i]
		if r.DeleteMarker.Delete {
			if err := imp.PutRole(ctx, r, true); err != nil {
				return nil, fmt.Errorf("delete role %s: %w", r.Name, err)
			}
			changes = append(changes, Change{Action: "delete", ObjectType: "role", Value: r.Name})
			continue
		}

		importedSet[r.Name] = true
		if existingRoles[r.Name] {
			if err := imp.PutRole(ctx, r, false); err != nil {
				return nil, fmt.Errorf("update role %s: %w", r.Name, err)
			}
			changes = append(changes, Change{Action: "update", ObjectType: "role", Value: r.Name})
		} else {
			if err := imp.PutRole(ctx, r, false); err != nil {
				return nil, fmt.Errorf("create role %s: %w", r.Name, err)
			}
			changes = append(changes, Change{Action: "create", ObjectType: "role", Value: r.Name})
		}
	}

	// Delete roles not in import
	if del {
		for roleName := range existingRoles {
			if !importedSet[roleName] {
				role := &appconfig.Role{Name: roleName, DeleteMarker: appconfig.DeleteMarker{Delete: true}}
				if err := imp.PutRole(ctx, role, true); err != nil {
					return nil, fmt.Errorf("delete role %s: %w", roleName, err)
				}
				changes = append(changes, Change{Action: "delete", ObjectType: "role", Value: roleName})
			}
		}
	}

	return changes, nil
}

func ImportPolicies(ctx context.Context, imp Importable, policies []appconfig.InlinePolicy, del bool) ([]Change, error) {
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
		if p.DeleteMarker.Delete {
			if err := imp.PutPolicy(ctx, p, true); err != nil {
				return nil, fmt.Errorf("delete policy %s: %w", p.Id, err)
			}
			changes = append(changes, Change{Action: "delete", ObjectType: "policy", Value: p.Id})
			continue
		}

		importedSet[p.Id] = true
		if existingSet[p.Id] {
			if err := imp.PutPolicy(ctx, p, false); err != nil {
				return nil, fmt.Errorf("update policy %s: %w", p.Id, err)
			}
			changes = append(changes, Change{Action: "update", ObjectType: "policy", Value: p.Id})
		} else {
			if err := imp.PutPolicy(ctx, p, false); err != nil {
				return nil, fmt.Errorf("create policy %s: %w", p.Id, err)
			}
			changes = append(changes, Change{Action: "create", ObjectType: "policy", Value: p.Id})
		}
	}

	// Delete policies not in import
	if del {
		for _, p := range existingPolicies {
			if !importedSet[p] {
				policy := &appconfig.InlinePolicy{Id: p, DeleteMarker: appconfig.DeleteMarker{Delete: true}}
				if err := imp.PutPolicy(ctx, policy, true); err != nil {
					return nil, fmt.Errorf("delete policy %s: %w", p, err)
				}
				changes = append(changes, Change{Action: "delete", ObjectType: "policy", Value: p})
			}
		}
	}

	return changes, nil
}
