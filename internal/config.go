package internal

import (
	"maps"
	"slices"
	"strings"
)

type RuntimeConfig struct {
	Accounts   []Account      `json:"accounts,omitempty"`
	Principals []Principal    `json:"principals,omitempty"`
	Roles      []Role         `json:"iam_roles,omitempty"`
	Policies   []CommonPolicy `json:"iam_policies,omitempty"`
	SsmActions []SsmAction    `json:"ssm_actions,omitempty"`

	accessMap map[string]struct{}
}

func (rt *RuntimeConfig) GenerateAccessMap() {
	ret := map[string]struct{}{}
	for _, p := range rt.Principals {
		for _, r := range p.Roles {
			roleType, accountId, name, valid := AccountRole(r).Parse()
			if !valid {
				continue
			}
			ret[roleAccessKey(roleType, p.Name, accountId, name)] = struct{}{}
		}
	}
	rt.accessMap = ret
}

func roleAccessKey(roleType string, principal string, accountId string, roleName string) string {
	b := strings.Builder{}
	b.Grow(len(principal) + len(accountId) + len(roleName) + len(roleType) + 3)
	b.WriteString(roleType)
	b.WriteByte(':')
	b.WriteString(principal)
	b.WriteByte(':')
	b.WriteString(accountId)
	b.WriteByte(':')
	b.WriteString(roleName)
	return b.String()
}

func (c *RuntimeConfig) RoleDetails(accountName, roleName string) (awsAccountId string, iamRoleName string, found bool) {
	for _, acc := range c.Accounts {
		if accountName != acc.Name {
			continue
		}
		for _, r := range acc.Roles {
			_, _, name, ok := r.Parse()
			if !ok || name != roleName {
				continue
			}
			return acc.AwsAccountId, name, true

		}
	}
	return "", "", false
}

func (c *RuntimeConfig) HasIamRoleAccess(accountId string, roleName string, principal ...string) bool {
	for _, p := range principal {
		_, ok := c.accessMap[roleAccessKey("iam", p, accountId, roleName)]
		if ok {
			return true
		}
	}
	return false
}
func (c *RuntimeConfig) HasSssmRoleAccess(accountId string, roleName string, principal ...string) bool {
	for _, p := range principal {
		_, ok := c.accessMap[roleAccessKey("ssm", p, accountId, roleName)]
		if ok {
			return true
		}
	}
	return false
}

func (c *RuntimeConfig) ListRoles(principal ...string) []string {
	roles := map[string]struct{}{}
	for _, rp := range principal {
		for _, p := range c.Principals {
			if p.Name == rp {
				for _, r := range p.Roles {
					roles[r] = struct{}{}
				}
			}
		}
	}
	return slices.Collect(maps.Keys(roles))
}
