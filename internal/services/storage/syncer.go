package storage

import (
	"context"
	"log"
	"maps"
	"slices"

	"github.com/chrisdd2/aws-login/appconfig"
)

type SyncStorer interface {
	Users(ctx context.Context) ([]appconfig.User, error)
	RolesForUser(ctx context.Context, username string) ([]string, error)
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

	rolesWithGrants := map[string]appconfig.RoleUserAttachment{}

	permissions := [][]string{
		{appconfig.RolePermissionCredentials},
		{appconfig.RolePermissionConsole},
		appconfig.RolePermissionAll,
	}
	for _, r := range roles {
		role, err := s.GetRole(ctx, r.RoleName)
		if err != nil {
			return nil, err
		}
		for i, roleTag := range []string{
			role.Metadata["sync_role_credentials"],
			role.Metadata["sync_role_console"],
			role.Metadata["sync_role_all"],
		} {
			if roleTag == "" {
				continue
			}
			rolesWithGrants[roleTag] = appconfig.RoleUserAttachment{
				RoleUserAttachmentId: appconfig.RoleUserAttachmentId{AccountName: r.AccountName, RoleName: r.RoleName},
				Permissions:          permissions[i],
			}
		}
	}

	attachments := map[appconfig.RoleUserAttachmentId]appconfig.RoleUserAttachment{}
	for i, u := range ssUsers {
		userRoles, err := ss.RolesForUser(ctx, u.Name)
		log.Println(u.Name, userRoles)
		if err != nil {
			return nil, err
		}
		for _, r := range userRoles {
			if superUserRole != "" && superUserRole == r {
				ssUsers[i].Superuser = appconfig.NullableBool(true)
				continue
			}
			at, found := rolesWithGrants[r]
			if !found {
				continue
			}
			// add attachment
			at.Username = u.Name
			attachments[at.RoleUserAttachmentId] = at
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
