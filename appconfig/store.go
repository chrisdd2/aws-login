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

//go:generate go run .../cmd/pg_generator -table=aws_login_policies
type Policy struct {
	Id       string `json:"id,omitempty" sql:"unique"`
	Document string `json:"document,omitempty"`
}

//go:generate go run .../cmd/pg_generator -table=aws_login_roles
type Role struct {
	Name               string        `json:"name,omitempty" sql:"unique"`
	ManagedPolicies    TextArray     `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration `json:"max_session_duration,omitempty"`
	CreatedBy          string        `json:"created_by,omitempty"`
	CreatedTime        time.Time     `json:"created_time,omitempty"`
	UpdatedBy          string        `json:"updated_by,omitempty"`
	UpdateTime         time.Time     `json:"update_time,omitempty"`
}

//go:generate go run .../cmd/pg_generator -table=aws_login_users
type User struct {
	FriendlyName string       `json:"friendly_name,omitempty"`
	Name         string       `json:"name,omitempty" sql:"unique" db:"id"`
	Superuser    NullableBool `json:"superuser,omitempty"`
	CreatedBy    string       `json:"created_by,omitempty"`
	CreatedTime  time.Time    `json:"created_time,omitempty"`
	UpdatedBy    string       `json:"updated_by,omitempty"`
	UpdateTime   time.Time    `json:"update_time,omitempty"`
}

//go:generate go run .../cmd/pg_generator -table=aws_login_accounts
type Account struct {
	Name         string    `json:"name,omitempty" sql:"unique"`
	AwsAccountId string    `json:"aws_account_id,omitempty"`
	CreatedBy    string    `json:"created_by,omitempty"`
	CreatedTime  time.Time `json:"created_time,omitempty"`
	UpdatedBy    string    `json:"updated_by,omitempty"`
	UpdateTime   time.Time `json:"update_time,omitempty"`
}

//go:generate go run .../cmd/pg_generator -table=aws_login_attachments
type Attachment struct {
	SourceId       string    `json:"source_id,omitempty" db:"id,filter"`
	TargetId       string    `json:"target_id,omitempty" db:"id,filter"`
	AttachmentType string    `json:"attachment_type,omitempty" db:"id,filter"`
	CreatedBy      string    `json:"created_by,omitempty"`
	CreatedTime    time.Time `json:"created_time,omitempty"`
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
