package imports

import (
	"context"
	"testing"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAction(t *testing.T) {
	tests := []struct {
		name   string
		del    bool
		exists bool
		want   string
	}{
		{"delete when marked for deletion", true, false, ActionDelete},
		{"delete when marked for deletion and exists", true, true, ActionDelete},
		{"update when exists", false, true, ActionUpdate},
		{"create when new", false, false, ActionCreate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := action(tt.del, tt.exists)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestImportUsers(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new user", func(t *testing.T) {
		imp := newMockImportable()
		users := []appconfig.User{{Name: "newuser"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Users: users}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionCreate, changes[0].Action)
		assert.Equal(t, ObjectTypeUser, changes[0].ObjectType)
		assert.Equal(t, "newuser", changes[0].Value)
		assert.Contains(t, imp.users, "newuser")
	})

	t.Run("updates existing user", func(t *testing.T) {
		imp := newMockImportable()
		imp.users = []string{"existinguser"}
		users := []appconfig.User{{Name: "existinguser"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Users: users}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 0)
	})

	t.Run("deletes user with delete flag", func(t *testing.T) {
		imp := newMockImportable()
		imp.users = []string{"todelete"}
		users := []appconfig.User{{Name: "todelete", CommonFields: appconfig.CommonFields{Delete: true}}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Users: users}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.Equal(t, ObjectTypeUser, changes[0].ObjectType)
		assert.Equal(t, "todelete", changes[0].Value)
	})

	t.Run("deletes users not in import when del is true", func(t *testing.T) {
		imp := newMockImportable()
		imp.users = []string{"user1", "user2"}
		users := []appconfig.User{{Name: "user1"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Users: users}, true)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.NotContains(t, imp.users, "user2")
	})

	t.Run("preserves users not in import when del is false", func(t *testing.T) {
		imp := newMockImportable()
		imp.users = []string{"user1", "user2"}
		users := []appconfig.User{{Name: "user1"}}

		_, err := ImportAll(ctx, imp, &storage.InMemoryStore{Users: users}, false)

		require.NoError(t, err)
		assert.Contains(t, imp.users, "user2")
	})

	t.Run("handles multiple users", func(t *testing.T) {
		imp := newMockImportable()
		users := []appconfig.User{
			{Name: "user1"},
			{Name: "user2"},
			{Name: "user3"},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Users: users}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 3)
		for i, c := range changes {
			assert.Equal(t, ActionCreate, c.Action)
			assert.Equal(t, ObjectTypeUser, c.ObjectType)
			assert.Equal(t, users[i].Name, c.Value)
		}
	})
}

func TestImportAccounts(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new account", func(t *testing.T) {
		imp := newMockImportable()
		accounts := []appconfig.Account{{Name: "newaccount"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Accounts: accounts}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionCreate, changes[0].Action)
		assert.Equal(t, ObjectTypeAccount, changes[0].ObjectType)
		assert.Equal(t, "newaccount", changes[0].Value)
	})

	t.Run("updates existing account", func(t *testing.T) {
		imp := newMockImportable()
		imp.accounts = []appconfig.Account{{Name: "existingaccount"}}
		accounts := []appconfig.Account{{Name: "existingaccount", AwsAccountId: "j"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Accounts: accounts}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionUpdate, changes[0].Action)
		assert.Equal(t, ObjectTypeAccount, changes[0].ObjectType)
	})

	t.Run("deletes account with delete flag", func(t *testing.T) {
		imp := newMockImportable()
		imp.accounts = []appconfig.Account{{Name: "todelete"}}
		accounts := []appconfig.Account{{Name: "todelete", CommonFields: appconfig.CommonFields{Delete: true}}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Accounts: accounts}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.Equal(t, ObjectTypeAccount, changes[0].ObjectType)
	})

	t.Run("deletes accounts not in import when del is true", func(t *testing.T) {
		imp := newMockImportable()
		imp.accounts = []appconfig.Account{{Name: "acc1"}, {Name: "acc2"}}
		accounts := []appconfig.Account{{Name: "acc1"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Accounts: accounts}, true)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
	})
}

func TestImportRoles(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new role", func(t *testing.T) {
		imp := newMockImportable()
		roles := []appconfig.Role{{Name: "newrole"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Roles: roles}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionCreate, changes[0].Action)
		assert.Equal(t, ObjectTypeRole, changes[0].ObjectType)
		assert.Equal(t, "newrole", changes[0].Value)
	})

	t.Run("updates existing role", func(t *testing.T) {
		imp := newMockImportable()
		imp.roles = []string{"existingrole"}
		roles := []appconfig.Role{{Name: "existingrole", MaxSessionDuration: time.Hour}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Roles: roles}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionUpdate, changes[0].Action)
		assert.Equal(t, ObjectTypeRole, changes[0].ObjectType)
	})

	t.Run("deletes role with delete flag", func(t *testing.T) {
		imp := newMockImportable()
		imp.roles = []string{"todelete"}
		roles := []appconfig.Role{{Name: "todelete", CommonFields: appconfig.CommonFields{Delete: true}}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Roles: roles}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.Equal(t, ObjectTypeRole, changes[0].ObjectType)
	})

	t.Run("deletes roles not in import when del is true", func(t *testing.T) {
		imp := newMockImportable()
		imp.roles = []string{"role1", "role2"}
		roles := []appconfig.Role{{Name: "role1"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Roles: roles}, true)

		require.NoError(t, err)
		require.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
	})
}

func TestImportPolicies(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new policy", func(t *testing.T) {
		imp := newMockImportable()
		policies := []appconfig.Policy{{Id: "newpolicy"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Policies: policies}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionCreate, changes[0].Action)
		assert.Equal(t, ObjectTypePolicy, changes[0].ObjectType)
		assert.Equal(t, "newpolicy", changes[0].Value)
	})

	t.Run("updates existing policy", func(t *testing.T) {
		imp := newMockImportable()
		imp.policies = []string{"existingpolicy"}
		policies := []appconfig.Policy{{Id: "existingpolicy", Document: "text"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Policies: policies}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionUpdate, changes[0].Action)
		assert.Equal(t, ObjectTypePolicy, changes[0].ObjectType)
	})

	t.Run("deletes policy with delete flag", func(t *testing.T) {
		imp := newMockImportable()
		imp.policies = []string{"todelete"}
		policies := []appconfig.Policy{{Id: "todelete", CommonFields: appconfig.CommonFields{Delete: true}}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Policies: policies}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.Equal(t, ObjectTypePolicy, changes[0].ObjectType)
	})

	t.Run("deletes policies not in import when del is true", func(t *testing.T) {
		imp := newMockImportable()
		imp.policies = []string{"pol1", "pol2"}
		policies := []appconfig.Policy{{Id: "pol1"}}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{Policies: policies}, true)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
	})
}

func TestImportRoleUserAttachments(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new attachment", func(t *testing.T) {
		imp := newMockImportable()
		attachments := []appconfig.RoleUserAttachment{
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "admin", AccountName: "prod"}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleUserAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionCreate, changes[0].Action)
		assert.Equal(t, ObjectTypeRoleUserAttachment, changes[0].ObjectType)
		assert.Equal(t, "user1|admin|prod", changes[0].Value)
	})

	t.Run("updates existing attachment", func(t *testing.T) {
		imp := newMockImportable()
		imp.roleUserAttachments = []appconfig.RoleUserAttachment{
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "admin", AccountName: "prod"}},
		}
		attachments := []appconfig.RoleUserAttachment{
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "admin", AccountName: "prod"}, Permissions: appconfig.TextArray{"console"}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleUserAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionUpdate, changes[0].Action)
		assert.Equal(t, ObjectTypeRoleUserAttachment, changes[0].ObjectType)
	})

	t.Run("deletes attachment with delete flag", func(t *testing.T) {
		imp := newMockImportable()
		imp.roleUserAttachments = []appconfig.RoleUserAttachment{
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "admin", AccountName: "prod"}},
		}
		attachments := []appconfig.RoleUserAttachment{
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "admin", AccountName: "prod"}, CommonFields: appconfig.CommonFields{Delete: true}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleUserAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.Equal(t, ObjectTypeRoleUserAttachment, changes[0].ObjectType)
	})

	t.Run("deletes attachments not in import when del is true", func(t *testing.T) {
		imp := newMockImportable()
		imp.roleUserAttachments = []appconfig.RoleUserAttachment{
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "admin", AccountName: "prod"}},
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user2", RoleName: "viewer", AccountName: "dev"}},
		}
		attachments := []appconfig.RoleUserAttachment{
			{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "admin", AccountName: "prod"}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleUserAttachments: attachments}, true)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
	})
}

func TestImportRolePolicyAttachments(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new attachment", func(t *testing.T) {
		imp := newMockImportable()
		attachments := []appconfig.RolePolicyAttachment{
			{RoleName: "admin", PolicyId: "policy1"},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RolePolicyAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionCreate, changes[0].Action)
		assert.Equal(t, ObjectTypeRolePolicyAttachment, changes[0].ObjectType)
		assert.Equal(t, "admin|policy1", changes[0].Value)
	})

	t.Run("updates existing attachment", func(t *testing.T) {
		imp := newMockImportable()
		imp.rolePolicyAttachments = []appconfig.RolePolicyAttachment{
			{RoleName: "admin", PolicyId: "policy1"},
		}
		attachments := []appconfig.RolePolicyAttachment{
			{RoleName: "admin", PolicyId: "policy1", CommonFields: appconfig.CommonFields{Metadata: appconfig.TextMap{"test": "test"}}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RolePolicyAttachments: attachments}, false)

		require.NoError(t, err)
		require.Len(t, changes, 1)
		assert.Equal(t, ActionUpdate, changes[0].Action)
		assert.Equal(t, ObjectTypeRolePolicyAttachment, changes[0].ObjectType)
	})

	t.Run("deletes attachment with delete flag", func(t *testing.T) {
		imp := newMockImportable()
		imp.rolePolicyAttachments = []appconfig.RolePolicyAttachment{
			{RoleName: "admin", PolicyId: "policy1"},
		}
		attachments := []appconfig.RolePolicyAttachment{
			{RoleName: "admin", PolicyId: "policy1", CommonFields: appconfig.CommonFields{Delete: true}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RolePolicyAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.Equal(t, ObjectTypeRolePolicyAttachment, changes[0].ObjectType)
	})

	t.Run("deletes attachments not in import when del is true", func(t *testing.T) {
		imp := newMockImportable()
		imp.rolePolicyAttachments = []appconfig.RolePolicyAttachment{
			{RoleName: "admin", PolicyId: "policy1"},
			{RoleName: "viewer", PolicyId: "policy2"},
		}
		attachments := []appconfig.RolePolicyAttachment{
			{RoleName: "admin", PolicyId: "policy1"},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RolePolicyAttachments: attachments}, true)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
	})
}

func TestImportRoleAccountAttachments(t *testing.T) {
	ctx := context.Background()

	t.Run("creates new attachment", func(t *testing.T) {
		imp := newMockImportable()
		attachments := []appconfig.RoleAccountAttachment{
			{RoleName: "admin", AccountName: "prod"},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleAccountAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionCreate, changes[0].Action)
		assert.Equal(t, ObjectTypeRoleAccountAttachment, changes[0].ObjectType)
		assert.Equal(t, "admin|prod", changes[0].Value)
	})

	t.Run("updates existing attachment", func(t *testing.T) {
		imp := newMockImportable()
		imp.roleAccountAttachments = []appconfig.RoleAccountAttachment{
			{RoleName: "admin", AccountName: "prod"},
		}
		attachments := []appconfig.RoleAccountAttachment{
			{RoleName: "admin", AccountName: "prod", CommonFields: appconfig.CommonFields{Metadata: appconfig.TextMap{"test": "test"}}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleAccountAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionUpdate, changes[0].Action)
		assert.Equal(t, ObjectTypeRoleAccountAttachment, changes[0].ObjectType)
	})

	t.Run("deletes attachment with delete flag", func(t *testing.T) {
		imp := newMockImportable()
		imp.roleAccountAttachments = []appconfig.RoleAccountAttachment{
			{RoleName: "admin", AccountName: "prod"},
		}
		attachments := []appconfig.RoleAccountAttachment{
			{RoleName: "admin", AccountName: "prod", CommonFields: appconfig.CommonFields{Delete: true}},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleAccountAttachments: attachments}, false)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
		assert.Equal(t, ObjectTypeRoleAccountAttachment, changes[0].ObjectType)
	})

	t.Run("deletes attachments not in import when del is true", func(t *testing.T) {
		imp := newMockImportable()
		imp.roleAccountAttachments = []appconfig.RoleAccountAttachment{
			{RoleName: "admin", AccountName: "prod"},
			{RoleName: "viewer", AccountName: "dev"},
		}
		attachments := []appconfig.RoleAccountAttachment{
			{RoleName: "admin", AccountName: "prod"},
		}

		changes, err := ImportAll(ctx, imp, &storage.InMemoryStore{RoleAccountAttachments: attachments}, true)

		require.NoError(t, err)
		assert.Len(t, changes, 1)
		assert.Equal(t, ActionDelete, changes[0].Action)
	})
}

func TestImportAll(t *testing.T) {
	ctx := context.Background()

	t.Run("imports all entity types", func(t *testing.T) {
		imp := newMockImportable()
		store := &storage.InMemoryStore{
			Users:    []appconfig.User{{Name: "user1"}},
			Accounts: []appconfig.Account{{Name: "acc1"}},
			Roles:    []appconfig.Role{{Name: "role1"}},
			Policies: []appconfig.Policy{{Id: "pol1"}},
			RolePolicyAttachments: []appconfig.RolePolicyAttachment{
				{RoleName: "role1", PolicyId: "pol1"},
			},
			RoleUserAttachments: []appconfig.RoleUserAttachment{
				{RoleUserAttachmentId: appconfig.RoleUserAttachmentId{Username: "user1", RoleName: "role1", AccountName: "acc1"}},
			},
			RoleAccountAttachments: []appconfig.RoleAccountAttachment{
				{RoleName: "role1", AccountName: "acc1"},
			},
		}

		changes, err := ImportAll(ctx, imp, store, false)

		require.NoError(t, err)
		// 1 user + 1 account + 1 role + 1 policy + 1 role_policy + 1 role_user + 1 role_account = 7
		assert.Len(t, changes, 7)

		// Verify all types are represented
		types := make(map[string]bool)
		for _, c := range changes {
			types[c.ObjectType] = true
		}
		assert.True(t, types[ObjectTypeUser])
		assert.True(t, types[ObjectTypeAccount])
		assert.True(t, types[ObjectTypeRole])
		assert.True(t, types[ObjectTypePolicy])
		assert.True(t, types[ObjectTypeRolePolicyAttachment])
		assert.True(t, types[ObjectTypeRoleUserAttachment])
		assert.True(t, types[ObjectTypeRoleAccountAttachment])
	})

	t.Run("handles mixed create/update/delete", func(t *testing.T) {
		imp := newMockImportable()
		imp.users = []string{"existing_user"}
		imp.accounts = []appconfig.Account{{Name: "existing_account"}}

		store := &storage.InMemoryStore{
			Users: []appconfig.User{
				{Name: "existing_user",FriendlyName: "new name"}, // update
				{Name: "new_user"},      // create
			},
			Accounts: []appconfig.Account{
				{Name: "existing_account",AwsAccountId: "new acc"}, // update
			},
		}

		changes, err := ImportAll(ctx, imp, store, true)

		require.NoError(t, err)
		// 2 users + 1 account = 3 changes
		assert.Len(t, changes, 3)
	})
}

func TestImportErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when PutUser fails", func(t *testing.T) {
		imp := newMockImportable()
		imp.putError = assert.AnError
		users := []appconfig.User{{Name: "user1"}}

		_, err := ImportAll(ctx, imp, &storage.InMemoryStore{Users: users}, false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "create user")
	})

	t.Run("returns error when PutAccount fails", func(t *testing.T) {
		imp := newMockImportable()
		imp.putError = assert.AnError
		accounts := []appconfig.Account{{Name: "acc1"}}

		_, err := ImportAll(ctx, imp, &storage.InMemoryStore{Accounts: accounts}, false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "create")
	})

	t.Run("returns error when PutRole fails", func(t *testing.T) {
		imp := newMockImportable()
		imp.putError = assert.AnError
		roles := []appconfig.Role{{Name: "role1"}}

		_, err := ImportAll(ctx, imp, &storage.InMemoryStore{Roles: roles}, false)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "create role")
	})
}
