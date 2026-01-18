package storage

import (
	"context"
	"maps"
	"slices"

	"github.com/chrisdd2/aws-login/appconfig"
)

type SyncStorer interface {
	Users(ctx context.Context) ([]appconfig.User, error)
	UsersForRole(ctx context.Context, roleName string) ([]string, error)
}

func Sync(ctx context.Context, ss SyncStorer, s Readable, superUserRole string) (*InMemoryStore, error) {
	ssUsers, err := ss.Users(ctx)
	if err != nil {
		return nil, err
	}
	// loop though our roles
	// based on the metadata, we identify the roles that a user might have
	// for each user of those role we create the appropriate attachment
	roles, err := s.ListRoleAccountAttachments(ctx, "", "")
	if err != nil {
		return nil, err
	}
	permissions := [][]string{
		{appconfig.RolePermissionCredentials},
		{appconfig.RolePermissionConsole},
		appconfig.RolePermissionAll,
	}

	// set super users
	superUsers := []string{}
	if superUserRole != "" {
		users, err := ss.UsersForRole(ctx, superUserRole)
		if err != nil {
			return nil, err
		}
		superUsers = users
	}
	for i, u := range ssUsers {
		ssUsers[i].Superuser = appconfig.NullableBool(slices.Contains(superUsers, u.Name))
	}

	attachments := map[appconfig.RoleUserAttachmentId]appconfig.RoleUserAttachment{}
	for _, r := range roles {
		role, err := s.GetRole(ctx, r.RoleName)
		if err != nil {
			return nil, err
		}
		credentialsRole := role.Metadata["sync_role_credentials"]
		consoleRole := role.Metadata["sync_role_console"]
		allRole := role.Metadata["sync_role_all"]
		for i, syncRole := range []string{credentialsRole, consoleRole, allRole} {
			if syncRole == "" {
				continue
			}
			roleUsers, err := ss.UsersForRole(ctx, syncRole)
			if err != nil {
				return nil, err
			}
			for _, ru := range roleUsers {
				id := appconfig.RoleUserAttachmentId{
					Username:    ru,
					AccountName: r.AccountName,
					RoleName:    r.RoleName,
				}
				attachments[id] = appconfig.RoleUserAttachment{
					RoleUserAttachmentId: id,
					Permissions:          deduplicate(append(attachments[id].Permissions, permissions[i]...)),
				}
			}
		}
	}

	return &InMemoryStore{
		Users:               ssUsers,
		RoleUserAttachments: slices.Collect(maps.Values(attachments)),
	}, nil
}

func deduplicate(ar []string) []string {
	ret := []string{}
	for _, a := range ar {
		if slices.Contains(ret, a) {
			continue
		}
		ret = append(ret, a)
	}
	return ret
}
