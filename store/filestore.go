package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"slices"

	"sigs.k8s.io/yaml"
)

type FileStore struct {
	MemoryStore
}

func (f *FileStore) LoadJson(r io.Reader) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	return dec.Decode(&f.MemoryStore)
}

func (f *FileStore) LoadYaml(r io.Reader) error {
	buf, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("io.ReadAll: %w", err)
	}
	if err := yaml.UnmarshalStrict(buf, &f.MemoryStore, yaml.DisallowUnknownFields); err != nil {
		return fmt.Errorf("yaml.UnmarshalStrict: %w", err)
	}
	return nil
}

var _memory Store = &MemoryStore{}

type MemoryStore struct {
	Resources           []*Resource
	ResourceAttachments []*ResourceAttachment
	UserPermissions     []*UserPermission
}

func matchOrEmpty(a, b string) bool {
	return a == "" || a == b
}
func matchOrEmptyArray(arr []string, a string) bool {
	return len(arr) == 0 || slices.Contains(arr, a)
}

func (f *MemoryStore) GetResources(ctx context.Context, resourceType string, ids ...string) ([]*Resource, error) {
	ret := []*Resource{}
	for _, r := range f.Resources {
		if matchOrEmpty(resourceType, r.Type) && matchOrEmptyArray(ids, r.Id) {
			ret = append(ret, r)
		}
	}
	return ret, nil
}
func (f *MemoryStore) SearchResources(ctx context.Context, resourceTypes ...string) (iter.Seq[*Resource], error) {
	return func(yield func(*Resource) bool) {
		for _, r := range f.Resources {
			if !matchOrEmptyArray(resourceTypes, r.Type) {
				continue
			}
			if !yield(r) {
				break
			}
		}
	}, nil
}

func (f *MemoryStore) GetResourceAttachments(ctx context.Context, attachmentType, resourceId, accountId string) ([]*ResourceAttachment, error) {
	ret := []*ResourceAttachment{}
	for _, r := range f.ResourceAttachments {
		if matchOrEmpty(attachmentType, r.Type) && matchOrEmpty(resourceId, r.ResourceId) && matchOrEmpty(accountId, r.TargetResourceId) {
			ret = append(ret, r)
		}
	}
	return ret, nil
}

func (f *MemoryStore) GetUserPermission(ctx context.Context, permissionType, userId, resourceId, accountId string) ([]*UserPermission, error) {
	ret := []*UserPermission{}
	for _, r := range f.UserPermissions {
		if matchOrEmpty(permissionType, r.Type) && matchOrEmpty(userId, r.UserId) && matchOrEmpty(resourceId, r.ResourceId) && matchOrEmpty(accountId, r.AccountId) {
			ret = append(ret, r)
		}
	}
	return ret, nil

}

func (f *MemoryStore) PutResource(ctx context.Context, objs ...*Resource) error {
	for _, obj := range objs {
		idx := slices.IndexFunc(f.Resources, func(r *Resource) bool {
			return r.Id == obj.Id && r.Type == obj.Type
		})
		if idx == -1 {
			f.Resources = append(f.Resources, obj)
			continue
		}
		f.Resources[idx] = obj
	}
	return nil
}
func (f *MemoryStore) PutResourceAttachment(ctx context.Context, objs ...*ResourceAttachment) error {
	for _, obj := range objs {
		idx := slices.IndexFunc(f.ResourceAttachments, func(r *ResourceAttachment) bool {
			return r.TargetResourceId == obj.TargetResourceId && r.ResourceId == obj.ResourceId && r.Type == obj.Type
		})
		if idx == -1 {
			f.ResourceAttachments = append(f.ResourceAttachments, obj)
			continue
		}
		f.ResourceAttachments[idx] = obj
	}
	return nil
}
func (f *MemoryStore) PutUserPermission(ctx context.Context, objs ...*UserPermission) error {
	for _, obj := range objs {
		idx := slices.IndexFunc(f.UserPermissions, func(r *UserPermission) bool {
			return r.UserId == obj.UserId && r.AccountId == obj.AccountId && r.ResourceId == obj.ResourceId && r.Type == obj.Type
		})
		if idx == -1 {
			f.UserPermissions = append(f.UserPermissions, obj)
			continue
		}
		f.UserPermissions[idx] = obj
	}
	return nil
}
