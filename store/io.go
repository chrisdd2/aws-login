package store

import (
	"context"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"time"
)

func Export(ctx context.Context, st Store) (*MemoryStore, error) {
	switch v := st.(type) {
	case *FileStore:
		return &v.MemoryStore, nil
	default:
		perms, err := st.GetUserPermission(ctx, "", "", "", "")
		if err != nil {
			return nil, err
		}
		resAtts, err := st.GetResourceAttachments(ctx, "", "", "")
		if err != nil {
			return nil, err
		}
		res, err := st.GetResources(ctx, "")
		if err != nil {
			return nil, err
		}
		return &MemoryStore{
			Resources:           res,
			ResourceAttachments: resAtts,
			UserPermissions:     perms,
		}, nil
	}
}

type Change struct {
	Action     string
	ObjectType string
	Value      string
}

func Import(ctx context.Context, st Store, ms *MemoryStore) ([]Change, error) {
	changes := []Change{}
	existing, err := Export(ctx, st)
	if err != nil {
		return nil, err
	}

	resources := []*Resource{}
	// naive implementation
	for _, res := range ms.Resources {
		existing, err := GetResource(ctx, existing, res.Type, res.Id)
		if err == nil && reflect.DeepEqual(existing, res) {
			// exists and its the same, skip
			continue
		}
		// doesn't exist or its changed
		resources = append(resources, res)
		changes = append(changes, Change{Action: ternary(res.Delete, "delete", ternary(existing == nil, "create", "update")), ObjectType: res.Type, Value: res.Id})
	}
	attachments := []*ResourceAttachment{}

	for _, res := range ms.ResourceAttachments {
		existing, err := GetResourceAttachment(ctx, existing, res.Type, res.ResourceId, res.TargetResourceId)
		if err == nil && reflect.DeepEqual(existing, res) {
			// exists and its the same, skip
			continue
		}
		// doesn't exist or its changed
		id := strings.Join([]string{res.ResourceId, res.TargetResourceId}, ",")
		attachments = append(attachments, res)
		changes = append(changes, Change{Action: ternary(res.Delete, "delete", ternary(existing == nil, "create", "update")), ObjectType: res.Type, Value: id})
	}

	perms := []*UserPermission{}

	for _, res := range ms.UserPermissions {
		existing, err := GetUserPermission(ctx, existing, res.Type, res.UserId, res.ResourceId, res.AccountId)
		if err == nil && reflect.DeepEqual(existing, res) {
			// exists and its the same, skip
			continue
		}
		// doesn't exist or its changed
		id := strings.Join([]string{res.UserId, res.ResourceId, res.AccountId}, ",")
		perms = append(perms, res)
		changes = append(changes, Change{Action: ternary(res.Delete, "delete", ternary(existing == nil, "create", "update")), ObjectType: res.Type, Value: id})
	}

	return changes, errors.Join(st.PutResource(ctx, resources...),
		st.PutResourceAttachment(ctx, attachments...),
		st.PutUserPermission(ctx, existing.UserPermissions...))
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

type RolePermission struct {
	AccountName string
	RoleName    string
	Permissions []string
}

type UserView struct {
	Name        string
	DisplayName string
	Roles       []RolePermission
	Superuser   bool
	MetaFields
}

type AccountView struct {
	Name         string
	AwsAccountId string
	Roles        []string
	MetaFields
}

type RoleView struct {
	Name               string
	ManagedPolicies    []string
	Policies           []string
	MaxSessionDuration time.Duration
	Accounts           []string
	MetaFields
}

type PolicyView struct {
	Id       string
	Document string
	Roles    []string
	MetaFields
}

func UsersView(ctx context.Context, st Store) ([]UserView, error) {
	ret := []UserView{}
	users, err := st.GetResources(ctx, ResourceTypeUser)
	if err != nil {
		return nil, err
	}
	for _, usr := range users {
		// check if superuser
		_, err := st.GetUserPermission(ctx, UserPermissionSuperUser, usr.Id, "", "")
		superuser := err == nil
		// get all role permissions
		perms, err := st.GetUserPermission(ctx, UserPermissionRole, usr.Id, "", "")
		if err != nil {
			return nil, err
		}
		roles := []RolePermission{}
		for _, p := range perms {
			roles = append(roles, RolePermission{AccountName: p.AccountId, RoleName: p.ResourceId, Permissions: slices.Collect(maps.Keys(p.Permissions))})
		}
		// gather up
		displayName := ternary(usr.Metadata["display_name"] == "", usr.Id, usr.Metadata["display_name"])
		ret = append(ret, UserView{
			Name:        usr.Id,
			DisplayName: displayName,
			Roles:       roles,
			Superuser:   superuser,
			MetaFields:  usr.MetaFields,
		})
	}
	return ret, nil
}

func AccountsView(ctx context.Context, st Store) ([]AccountView, error) {
	ret := []AccountView{}
	accounts, err := st.GetResources(ctx, ResourceTypeAccount)
	if err != nil {
		return nil, err
	}
	for _, acc := range accounts {
		doc := GetDocument[AccountDocument](acc)
		atts, err := st.GetResourceAttachments(ctx, AccountAttachmentRole, "", acc.Id)
		if err != nil {
			return nil, err
		}
		roles := []string{}
		for _, a := range atts {
			roles = append(roles, a.ResourceId)
		}
		ret = append(ret, AccountView{
			AwsAccountId: doc.AwsAccountId,
			Name:         acc.Id,
			Roles:        roles,
			MetaFields:   acc.MetaFields,
		})
	}
	return ret, nil

}

func RolesView(ctx context.Context, st Store) ([]RoleView, error) {
	ret := []RoleView{}
	roles, err := st.GetResources(ctx, ResourceTypeRole)
	if err != nil {
		return nil, err
	}
	for _, role := range roles {
		doc := GetDocument[RoleDocument](role)
		atts, err := st.GetResourceAttachments(ctx, AccountAttachmentRole, role.Id, "")
		if err != nil {
			return nil, err
		}
		accounts := []string{}
		for _, a := range atts {
			accounts = append(accounts, a.TargetResourceId)
		}
		atts, err = st.GetResourceAttachments(ctx, RoleAttachmentPolicy, role.Id, "")
		if err != nil {
			return nil, err
		}
		policies := []string{}
		for _, a := range atts {
			policies = append(policies, a.TargetResourceId)
		}
		ret = append(ret, RoleView{
			Name:               role.Id,
			ManagedPolicies:    doc.ManagedPolicies,
			Accounts:           accounts,
			MaxSessionDuration: doc.ParsedMaxSessionDuration(),
			Policies:           policies,
			MetaFields:         role.MetaFields,
		})
	}
	return ret, nil
}

func PoliciesView(ctx context.Context, st Store) ([]PolicyView, error) {
	ret := []PolicyView{}
	policies, err := st.GetResources(ctx, ResourceTypePolicy)
	if err != nil {
		return nil, err
	}
	for _, p := range policies {
		atts, err := st.GetResourceAttachments(ctx, AccountAttachmentRole, "", p.Id)
		if err != nil {
			return nil, err
		}
		roles := []string{}
		for _, a := range atts {
			roles = append(roles, a.ResourceId)
		}
		ret = append(ret, PolicyView{
			Id:         p.Id,
			Document:   p.Document,
			Roles:      roles,
			MetaFields: p.MetaFields,
		})
	}
	return ret, nil
}
