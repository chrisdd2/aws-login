package store

import (
	"database/sql/driver"
	"fmt"
	"strings"
)

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

func (r *Resource) Scan() []any {
	return []any{&r.Id, &r.Type, &r.Document, &r.Metadata, &r.Disabled}
}

func (a *ResourceAttachment) Scan() []any {
	return []any{&a.ResourceId, &a.TargetResourceId, &a.Type, &a.Metadata, &a.Disabled}
}
func (u *UserPermission) Scan() []any {
	return []any{&u.UserId, &u.ResourceId, &u.AccountId, &u.Type, &u.Permissions,&u.Metadata,&u.Disabled}
}
