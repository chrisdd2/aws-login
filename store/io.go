package store

import (
	"context"
	"errors"
	"reflect"
	"strings"
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
