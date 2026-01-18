package appconfig

import (
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

var RolePermissionAll []string = []string{RolePermissionConsole, RolePermissionCredentials}

// import needs a delete flag
type CommonFields struct {
	Delete   bool         `json:"delete,omitempty"`
	Disabled NullableBool `json:"disabled,omitempty"`
	Metadata TextMap      `json:"metadata,omitempty"`
}

type Policy struct {
	Id       string `json:"id,omitempty"`
	Document string `json:"document,omitempty"`
	CommonFields
}

type Role struct {
	Name               string        `json:"name,omitempty"`
	ManagedPolicies    TextArray     `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration `json:"max_session_duration,omitempty"`
	CommonFields
}

type User struct {
	FriendlyName string       `json:"friendly_name,omitempty"`
	Name         string       `json:"name,omitempty"`
	Superuser    NullableBool `json:"superuser,omitempty"`
	CommonFields
}

type Account struct {
	Name         string `json:"name,omitempty"`
	AwsAccountId string `json:"aws_account_id,omitempty"`
	CommonFields
}

type RoleUserAttachmentId struct {
	Username    string `json:"user_name,omitempty"`
	RoleName    string `json:"role_name,omitempty"`
	AccountName string `json:"account_name,omitempty"`
}

type RoleUserAttachment struct {
	RoleUserAttachmentId
	Permissions TextArray `json:"permissions,omitempty"`
	CommonFields
}

type RoleAccountAttachment struct {
	RoleName    string `json:"role_name,omitempty"`
	AccountName string `json:"account_name,omitempty"`
	CommonFields
}

type RolePolicyAttachment struct {
	RoleName string `json:"role_name,omitempty"`
	PolicyId string `json:"policy_id,omitempty"`
	CommonFields
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
	*ta = strings.Split(vstr, ",")
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
