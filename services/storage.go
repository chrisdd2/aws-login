package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"slices"

	"github.com/chrisdd2/aws-login/appconfig"

	"sigs.k8s.io/yaml"
)

var ErrUserNotFound = errors.New("UserNotFound")

type Storage interface {
	ListRolesForAccount(ctx context.Context, accountId string) ([]*appconfig.Role, error)

	ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]*appconfig.RoleAttachment, error)
	GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error)

	GetRole(ctx context.Context, name string) (*appconfig.Role, error)
	GetUser(ctx context.Context, name string) (*appconfig.User, error)
	GetAccount(ctx context.Context, id string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)
}

type Store struct {
	Users         []appconfig.User         `json:"users,omitempty"`
	Accounts      []appconfig.Account      `json:"accounts,omitempty"`
	Roles         []appconfig.Role         `json:"roles,omitempty"`
	Policies      []appconfig.InlinePolicy `json:"policies,omitempty"`
	adminUsername string
	adminUser     *appconfig.User
}

func (s *Store) Reset() {
	s.Users = nil
	s.Accounts = nil
	s.Roles = nil
	s.Policies = nil
}

func (s *Store) Merge(o *Store, inPlace bool) *Store {
	adminUsername := s.adminUsername
	if adminUsername == "" {
		adminUsername = o.adminUsername
	}
	var ret *Store
	if inPlace {
		ret = s
		s.adminUsername = adminUsername
	} else {
		ret = &Store{adminUsername: adminUsername}
	}
	ret.Users = slices.Concat(s.Users, o.Users)
	ret.Accounts = slices.Concat(s.Accounts, o.Accounts)
	ret.Roles = slices.Concat(s.Roles, o.Roles)
	ret.Policies = slices.Concat(s.Policies, o.Policies)
	return ret
}
func (s *Store) LoadYaml(r io.Reader) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(buf, s)
}
func (s *Store) LoadJson(r io.Reader) error {
	return json.NewDecoder(r).Decode(&s)
}

func NewStaticStore(adminUsername string) *Store {
	return &Store{adminUsername: adminUsername}
}

func (s *Store) GetAccount(ctx context.Context, name string) (*appconfig.Account, error) {
	idx := slices.IndexFunc(s.Accounts, func(acc appconfig.Account) bool {
		return name == acc.Name
	})
	if idx != -1 {
		return &s.Accounts[idx], nil
	}
	return nil, errors.New("AccountNotFound")
}

func (s *Store) ListRolesForAccount(ctx context.Context, accountName string) ([]*appconfig.Role, error) {
	roles := []*appconfig.Role{}
	for _, role := range s.Roles {
		if accountName == "" || slices.Contains(role.AssociatedAccounts, accountName) {
			roles = append(roles, &role)
		}
	}
	return roles, nil
}
func (s *Store) ListRolePermissions(ctx context.Context, userName string, roleName string, accountName string) ([]*appconfig.RoleAttachment, error) {
	if userName == "" {
		return nil, errors.New("username must be provided")
	}
	user, err := s.GetUser(ctx, userName)
	if err != nil {
		return nil, fmt.Errorf("storage.GetUser: %w", err)
	}
	attachments := user.Roles
	// superusers see the same roles as the admin user
	if user.Superuser {
		attachments = s.createAdminUser().Roles
	}
	ats := []*appconfig.RoleAttachment{}
	for _, at := range attachments {
		if (accountName == "" || at.AccountName == accountName) && (roleName == "" || at.RoleName == roleName) {
			ats = append(ats, &at)
		}
	}
	return ats, nil
}
func (s *Store) GetInlinePolicy(ctx context.Context, id string) (*appconfig.InlinePolicy, error) {
	idx := slices.IndexFunc(s.Policies, func(acc appconfig.InlinePolicy) bool {
		return id == acc.Id
	})
	if idx != -1 {
		return &s.Policies[idx], nil
	}
	return nil, errors.New("PolicyNotFound")
}
func (s *Store) GetUser(ctx context.Context, id string) (*appconfig.User, error) {
	if id == s.adminUsername {
		return s.createAdminUser(), nil
	}
	idx := slices.IndexFunc(s.Users, func(acc appconfig.User) bool {
		return id == acc.Name
	})
	if idx != -1 {
		return &s.Users[idx], nil
	}
	return nil, ErrUserNotFound
}

func (s *Store) GetRole(ctx context.Context, name string) (*appconfig.Role, error) {
	idx := slices.IndexFunc(s.Roles, func(acc appconfig.Role) bool {
		return name == acc.Name
	})
	if idx != -1 {
		return &s.Roles[idx], nil
	}
	return nil, errors.New("RoleNotFound")
}

func (s *Store) createAdminUser() *appconfig.User {
	if s.adminUser != nil {
		return s.adminUser
	}
	// make a role attachment for every role available
	attachments := []appconfig.RoleAttachment{}
	for _, role := range s.Roles {
		for _, acc := range role.AssociatedAccounts {
			attachments = append(attachments,
				appconfig.RoleAttachment{
					RoleName:    role.Name,
					AccountName: acc,
					Permissions: []string{appconfig.RolePermissionConsole, appconfig.RolePermissionCredentials}})
		}
	}
	user := &appconfig.User{
		Name:      s.adminUsername,
		Superuser: true,
		Email:     "admin@admin",
		Roles:     attachments,
	}
	s.adminUser = user
	return user

}

func (s *Store) ListAccounts(ctx context.Context) ([]*appconfig.Account, error) {
	ret := make([]*appconfig.Account, 0, len(s.Accounts))
	for _, acc := range s.Accounts {
		ret = append(ret, &acc)
	}
	return ret, nil
}
