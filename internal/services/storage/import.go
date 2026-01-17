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
		if u.Delete {
			if err := imp.PutUser(ctx, u); err != nil {
				return nil, fmt.Errorf("delete user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: "delete", ObjectType: "user", Value: u.Name})
			continue
		}

		importedSet[u.Name] = true
		if existingSet[u.Name] {
			// Update existing user
			if err := imp.PutUser(ctx, u); err != nil {
				return nil, fmt.Errorf("update user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: "update", ObjectType: "user", Value: u.Name})
		} else {
			// Create new user
			if err := imp.PutUser(ctx, u); err != nil {
				return nil, fmt.Errorf("create user %s: %w", u.Name, err)
			}
			changes = append(changes, Change{Action: "create", ObjectType: "user", Value: u.Name})
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
			changes = append(changes, Change{Action: "delete", ObjectType: "account", Value: a.Name})
			continue
		}

		importedSet[a.Name] = true
		if existingSet[a.Name] {
			if err := imp.PutAccount(ctx, a); err != nil {
				return nil, fmt.Errorf("update account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: "update", ObjectType: "account", Value: a.Name})
		} else {
			if err := imp.PutAccount(ctx, a); err != nil {
				return nil, fmt.Errorf("create account %s: %w", a.Name, err)
			}
			changes = append(changes, Change{Action: "create", ObjectType: "account", Value: a.Name})
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
				changes = append(changes, Change{Action: "delete", ObjectType: "account", Value: a.Name})
			}
		}
	}

	return changes, nil
}

func ImportRoles(ctx context.Context, imp Importable, roles []appconfig.Role, del bool) ([]Change, error) {
	return nil, nil
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
			ObjectType: "policy",
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
				changes = append(changes, Change{Action: "delete", ObjectType: "policy", Value: p})
			}
		}
	}

	return changes, nil
}

func action(del bool, exists bool) string {
	if del {
		return "delete"
	}
	if exists {
		return "update"
	}
	return "create"
}
