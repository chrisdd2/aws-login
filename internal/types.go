package internal

import (
	"strings"
	"time"
)

const (
	RolePermissionInvalid     = "invalid"
	RolePermissionCredentials = "credential"
	RolePermissionConsole     = "console"
)

var RolePermissionAll []string = []string{RolePermissionConsole, RolePermissionCredentials}

type AccountRole string
type Account struct {
	Name         string            `json:"name,omitempty"`
	AwsAccountId string            `json:"aws_account_id,omitempty"`
	Roles        []AccountRole     `json:"roles,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

type SsmInstance struct {
	Name                string              `json:"name,omitempty"`
	Ids                 []string            `json:"ids,omitempty"`
	TagFilter           map[string][]string `json:"tag_filter,omitempty"`
	PortForwardingHosts []string            `json:"port_forwarding_hosts,omitempty"`
	ShellAccess         bool                `json:"shell_access,omitempty"`
}

type Role struct {
	Name               string            `json:"name,omitempty" sql:"unique"`
	ManagedPolicies    []string          `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration     `json:"max_session_duration,omitempty"`
	Policies           []string          `json:"policies,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
}

type Principal struct {
	Name  string            `json:"name,omitempty"`
	Claim string            `json:"claim,omitempty"`
	Roles []string          `json:"roles,omitempty"`
	Tags  map[string]string `json:"tags,omitempty"`
}

type CommonPolicy struct {
	Name string `json:"name,omitempty"`
	Text string `json:"text,omitempty"`
}

type Manifest struct {
	Accounts     []Account      `json:"accounts,omitempty"`
	Principals   []Principal    `json:"principals,omitempty"`
	Roles        []Role         `json:"iam_roles,omitempty"`
	Policies     []CommonPolicy `json:"iam_policies,omitempty"`
	SsmInstances []SsmInstance  `json:"ssm_instances,omitempty"`
}

func (v AccountRole) Parse() (roleType, name string, valid bool) {
	after, found := strings.CutPrefix(string(v), "arn:iam::role/")
	if found {
		return "iam", after, true
	}
	after, found = strings.CutPrefix(string(v), "arn:ssm::instance/")
	if found {
		return "ssm", after, true
	}
	return "", "", false
}

func ParsePrincipalRoleString(v string) (AccountRole, error) {
}
