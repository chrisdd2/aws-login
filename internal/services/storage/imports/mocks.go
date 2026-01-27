package imports

import (
	"context"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services/storage"
)

// mockImportable is a mock implementation of Importable for testing
type mockImportable struct {
	users                  []string
	accounts               []appconfig.Account
	roles                  []string
	policies               []string
	roleUserAttachments    []appconfig.RoleUserAttachment
	rolePolicyAttachments  []appconfig.RolePolicyAttachment
	roleAccountAttachments []appconfig.RoleAccountAttachment
	putError               error
	getError               error
}

func (m *mockImportable) PutUser(ctx context.Context, u *appconfig.User) error {
	if m.putError != nil {
		return m.putError
	}
	if u.Delete {
		for i, name := range m.users {
			if name == u.Name {
				m.users = append(m.users[:i], m.users[i+1:]...)
				break
			}
		}
		return nil
	}
	m.users = append(m.users, u.Name)
	return nil
}

func (m *mockImportable) PutAccount(ctx context.Context, a *appconfig.Account) error {
	if m.putError != nil {
		return m.putError
	}
	if a.Delete {
		for i, acc := range m.accounts {
			if acc.Name == a.Name {
				m.accounts = append(m.accounts[:i], m.accounts[i+1:]...)
				break
			}
		}
		return nil
	}
	m.accounts = append(m.accounts, *a)
	return nil
}

func (m *mockImportable) PutPolicy(ctx context.Context, p *appconfig.Policy) error {
	if m.putError != nil {
		return m.putError
	}
	if p.Delete {
		for i, id := range m.policies {
			if id == p.Id {
				m.policies = append(m.policies[:i], m.policies[i+1:]...)
				break
			}
		}
		return nil
	}
	m.policies = append(m.policies, p.Id)
	return nil
}

func (m *mockImportable) PutRole(ctx context.Context, r *appconfig.Role) error {
	if m.putError != nil {
		return m.putError
	}
	if r.Delete {
		for i, name := range m.roles {
			if name == r.Name {
				m.roles = append(m.roles[:i], m.roles[i+1:]...)
				break
			}
		}
		return nil
	}
	m.roles = append(m.roles, r.Name)
	return nil
}

func (m *mockImportable) PutRoleUserAttachment(ctx context.Context, a *appconfig.RoleUserAttachment) error {
	if m.putError != nil {
		return m.putError
	}
	if a.Delete {
		for i, at := range m.roleUserAttachments {
			if at.Username == a.Username && at.RoleName == a.RoleName && at.AccountName == a.AccountName {
				m.roleUserAttachments = append(m.roleUserAttachments[:i], m.roleUserAttachments[i+1:]...)
				break
			}
		}
		return nil
	}
	m.roleUserAttachments = append(m.roleUserAttachments, *a)
	return nil
}

func (m *mockImportable) PutRolePolicyAttachment(ctx context.Context, a *appconfig.RolePolicyAttachment) error {
	if m.putError != nil {
		return m.putError
	}
	if a.Delete {
		for i, at := range m.rolePolicyAttachments {
			if at.RoleName == a.RoleName && at.PolicyId == a.PolicyId {
				m.rolePolicyAttachments = append(m.rolePolicyAttachments[:i], m.rolePolicyAttachments[i+1:]...)
				break
			}
		}
		return nil
	}
	m.rolePolicyAttachments = append(m.rolePolicyAttachments, *a)
	return nil
}

func (m *mockImportable) PutRoleAccountAttachment(ctx context.Context, a *appconfig.RoleAccountAttachment) error {
	if m.putError != nil {
		return m.putError
	}
	if a.Delete {
		for i, at := range m.roleAccountAttachments {
			if at.RoleName == a.RoleName && at.AccountName == a.AccountName {
				m.roleAccountAttachments = append(m.roleAccountAttachments[:i], m.roleAccountAttachments[i+1:]...)
				break
			}
		}
		return nil
	}
	m.roleAccountAttachments = append(m.roleAccountAttachments, *a)
	return nil
}

func (m *mockImportable) ListUsers(ctx context.Context) ([]string, error) {
	return m.users, nil
}

func (m *mockImportable) ListAccounts(ctx context.Context) ([]appconfig.Account, error) {
	return m.accounts, nil
}

func (m *mockImportable) ListRoles(ctx context.Context) ([]string, error) {
	return m.roles, nil
}

func (m *mockImportable) ListPolicies(ctx context.Context) ([]string, error) {
	return m.policies, nil
}

func (m *mockImportable) ListRoleUserAttachments(ctx context.Context, username string, roleName string, accountName string) ([]appconfig.RoleUserAttachment, error) {
	var result []appconfig.RoleUserAttachment
	for _, at := range m.roleUserAttachments {
		if (username == "" || at.Username == username) &&
			(roleName == "" || at.RoleName == roleName) &&
			(accountName == "" || at.AccountName == accountName) {
			result = append(result, at)
		}
	}
	return result, nil
}

func (m *mockImportable) ListRolePolicyAttachments(ctx context.Context, roleName string) ([]appconfig.RolePolicyAttachment, error) {
	var result []appconfig.RolePolicyAttachment
	for _, at := range m.rolePolicyAttachments {
		if roleName == "" || at.RoleName == roleName {
			result = append(result, at)
		}
	}
	return result, nil
}

func (m *mockImportable) ListRoleAccountAttachments(ctx context.Context, roleName string, accountName string) ([]appconfig.RoleAccountAttachment, error) {
	var result []appconfig.RoleAccountAttachment
	for _, at := range m.roleAccountAttachments {
		if (roleName == "" || at.RoleName == roleName) &&
			(accountName == "" || at.AccountName == accountName) {
			result = append(result, at)
		}
	}
	return result, nil
}

func (m *mockImportable) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	for _, n := range m.roles {
		if n == name {
			return &appconfig.Role{Name: name}, nil
		}
	}
	return nil, storage.ErrRoleNotFound
}

func (m *mockImportable) GetUser(ctx context.Context, name string) (*appconfig.User, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	for _, n := range m.users {
		if n == name {
			return &appconfig.User{Name: name}, nil
		}
	}
	return nil, storage.ErrUserNotFound
}

func (m *mockImportable) GetAccount(ctx context.Context, id string) (*appconfig.Account, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	for _, acc := range m.accounts {
		if acc.Name == id {
			return &appconfig.Account{Name: acc.Name, AwsAccountId: acc.AwsAccountId}, nil
		}
	}
	return nil, storage.ErrAccountNotFound
}

func (m *mockImportable) GetPolicy(ctx context.Context, id string) (*appconfig.Policy, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	for _, pid := range m.policies {
		if pid == id {
			return &appconfig.Policy{Id: id}, nil
		}
	}
	return nil, storage.ErrPolicyNotFound
}

func newMockImportable() *mockImportable {
	return &mockImportable{
		users:    []string{},
		accounts: []appconfig.Account{},
		roles:    []string{},
		policies: []string{},
	}
}
