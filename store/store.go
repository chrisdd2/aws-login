package store

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
)

var ErrResourceNotFound = errors.New("object not found")
var ErrAttachmentNotFound = errors.New("attachment not found")
var ErrPermissionNotFound = errors.New("permission not found")
var ErrDisabled = errors.New("object disabled")

const (
	ResourceTypeRole    = "role"
	ResourceTypeAccount = "account"
	ResourceTypeUser    = "user"
	ResourceTypePolicy  = "policy"

	RoleAttachmentPolicy  = "policy"
	AccountAttachmentRole = "role"
	AccountAttachmentSsm  = "ssm"

	UserPermissionRole      = "role"
	UserPermissionSsm       = "ssm"
	UserPermissionSuperUser = "superuser"
)
const (
	RolePermissionInvalid     = "invalid"
	RolePermissionCredentials = "credential"
	RolePermissionConsole     = "console"
)

var RolePermissionAll []string = []string{RolePermissionConsole, RolePermissionCredentials}

type MetaFields struct {
	Metadata map[string]string `json:"metadata,omitempty"`
	Disabled NullableBool      `json:"disabled,omitempty"`
	Delete   bool              `json:"delete,omitempty"`
}

type Resource struct {
	Id       string `json:"id,omitempty"`
	Type     string `json:"type,omitempty"`
	Document string `json:"document,omitempty"`
	MetaFields
}

type ResourceAttachment struct {
	ResourceId       string `json:"resource_id,omitempty"`
	TargetResourceId string `json:"account_id,omitempty"`
	Type             string `json:"type,omitempty"`
	MetaFields
}

type UserPermission struct {
	UserId      string  `json:"user_id,omitempty"`
	ResourceId  string  `json:"resource_id,omitempty"`
	AccountId   string  `json:"account_id,omitempty"`
	Type        string  `json:"type,omitempty"`
	Permissions TextMap `json:"permissions,omitempty"`
	MetaFields
}

type Store interface {
	PutResource(ctx context.Context, objs ...*Resource) error
	GetResources(ctx context.Context, resourceType string, ids ...string) ([]*Resource, error)
	SearchResources(ctx context.Context, resourceTypes ...string) (iter.Seq[*Resource], error)

	PutResourceAttachment(ctx context.Context, objs ...*ResourceAttachment) error
	GetResourceAttachments(ctx context.Context, attachmentType, resourceId, targetId string) ([]*ResourceAttachment, error)

	PutUserPermission(ctx context.Context, objs ...*UserPermission) error
	GetUserPermission(ctx context.Context, permissionType, userId, resourceId, accountId string) ([]*UserPermission, error)
}

func GetDocument[T any](r *Resource) T {
	v := *new(T)
	json.Unmarshal([]byte(r.Document), &v)
	return v
}

func GetResource(ctx context.Context, st Store, resourceType string, id string) (*Resource, error) {
	ret, err := st.GetResources(ctx, resourceType, id)
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return nil, ErrResourceNotFound
	}
	return ret[0], nil
}
func GetResourceAttachment(ctx context.Context, st Store, attachmentType string, resourceId string, targetId string) (*ResourceAttachment, error) {
	ret, err := st.GetResourceAttachments(ctx, attachmentType, resourceId, targetId)
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return nil, ErrAttachmentNotFound
	}
	return ret[0], nil
}

func GetUserPermission(ctx context.Context, st Store, permissionType, userId, resourceId, accountId string) (*UserPermission, error) {
	ret, err := st.GetUserPermission(ctx, permissionType, userId, resourceId, accountId)
	if err != nil {
		return nil, err
	}
	if len(ret) == 0 {
		return nil, ErrPermissionNotFound
	}
	return ret[0], nil
}
