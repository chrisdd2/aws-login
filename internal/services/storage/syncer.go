package storage

import (
	"context"

	"github.com/chrisdd2/aws-login/appconfig"
)

type SyncStorer interface {
	Users(ctx context.Context) ([]appconfig.User, error)
	UsersForRole(ctx context.Context, roleName string) ([]string, error)
}

func Sync(ctx context.Context, ss SyncStorer, s Readable) (*InMemoryStore, error) {
	ssUsers, err := ss.Users(ctx)
	if err != nil {
		return nil, err
	}
	// loop though our roles
	// based on the metadata, we identify the roles that a user might have
	// for each user of those role we create the appropriate attachment
	attachments := []appconfig.RoleUserAttachment{}
	roles, err := s.ListRoleAccountAttachments(ctx, "", "")
	if err != nil {
		return nil, err
	}
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
				attachments = append(attachments, appconfig.RoleUserAttachment{
					Username:    ru,
					AccountName: r.AccountName,
					RoleName:    r.RoleName,
					Permissions: permissions[i],
				})
			}
		}
	}
	return &InMemoryStore{Users: ssUsers, RoleUserAttachments: attachments}, nil
}
