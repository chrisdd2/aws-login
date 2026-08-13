package storage

import (
	"context"
	"database/sql/driver"
	"fmt"
	"strings"
	"time"
)

const (
	RolePermissionInvalid     = "invalid"
	RolePermissionCredentials = "credential"
	RolePermissionConsole     = "console"
)

type Model[T any, Y any, Z any] interface {
	Put(ctx context.Context, item *T, del bool) error
	Get(ctx context.Context, id Y) error
	List(ctx context.Context, filter Z) ([]T, error)
}

var RolePermissionAll []string = []string{RolePermissionConsole, RolePermissionCredentials}

type Policy struct {
	Id       string `json:"id,omitempty" sql:"unique"`
	Document string `json:"document,omitempty"`
}

type Role struct {
	AccountName        string        `json:"account_name,omitempty" sql:"id"`
	AwsAccountId       string        `json:"aws_account_id,omitempty"`
	RoleName           string        `json:"role_name,omitempty" sql:"id"`
	Description        string        `json:"description,omitempty"`
	ManagedPolicies    TextArray     `json:"managed_policies,omitempty"`
	InlinePolicies     TextArray     `json:"inline_policies,omitempty"`
	MaxSessionDuration time.Duration `json:"max_session_duration,omitempty"`
	Tags               TextMap       `json:"tags,omitempty"`
}

type User struct {
	Name         string       `json:"name,omitempty" sql:"unique"`
	FriendlyName string       `json:"friendly_name,omitempty"`
	Superuser    NullableBool `json:"superuser,omitempty"`
	Tags         TextMap      `json:"tags,omitempty"`
}

type Account struct {
	Name         string  `json:"name,omitempty" sql:"unique"`
	AwsAccountId string  `json:"aws_account_id,omitempty"`
	Description  string  `json:"description,omitempty"`
	Enabled      bool    `json:"enabled,omitempty"`
	Tags         TextMap `json:"tags,omitempty"`
}
type RolePermission struct {
	Username    string    `json:"user_name,omitempty" sql:"unique"`
	AccountName string    `json:"account_name,omitempty" sql:"unique"`
	RoleName    string    `json:"role_name,omitempty" sql:"unique"`
	Permissions TextArray `json:"permissions,omitempty"`
}

type TextMap map[string]string

// Scan implements the [Scanner] interface.
func (tm *TextMap) Scan(value any) error {
	ret := map[string]string{}
	vstr, ok := value.(string)
	if ok {
		for i := range strings.SplitSeq(vstr, ",") {
			k, v, ok := strings.Cut(i, ":")
			if !ok {
				continue
			}
			k = strings.TrimSpace(k)
			v = strings.TrimSpace(v)
			if k == "" || v == "" {
				continue
			}
			ret[k] = v
		}
	}
	*tm = ret
	return nil
}

func (tm *TextMap) Value() (driver.Value, error) {
	var b strings.Builder
	for k, v := range *tm {
		fmt.Fprintf(&b, "%s:%s,", k, v)
	}
	return strings.TrimSuffix(b.String(), ","), nil
}

type TextArray []string

func (ta *TextArray) Scan(value any) error {
	vstr, ok := value.(string)
	if !ok {
		return nil
	}
	ret := []string{}
	for v := range strings.SplitSeq(vstr, ",") {
		v := strings.TrimSpace(v)
		if v == "" {
			continue
		}
		ret = append(ret, v)
	}
	*ta = ret
	return nil
}

func (tm *TextArray) Value() (driver.Value, error) {
	return strings.Join([]string(*tm), ","), nil
}

type NullableBool bool

func (b *NullableBool) Scan(value any) error {
	v, ok := value.(bool)
	if !ok {
		return nil
	}
	*b = NullableBool(v)
	return nil
}

func (b *NullableBool) Value() (driver.Value, error) {
	return *b, nil
}
