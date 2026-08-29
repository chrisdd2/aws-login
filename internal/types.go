package internal

import (
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

type AccountRole string
type Account struct {
	Name         string            `json:"name,omitempty"`
	AwsAccountId string            `json:"aws_account_id,omitempty"`
	Roles        []AccountRole     `json:"roles,omitempty"`
	Tags         map[string]string `json:"tags,omitempty"`
}

type SsmAction struct {
	Name                 string              `json:"name,omitempty"`
	Region               string              `json:"region,omitempty"`
	Ids                  []string            `json:"ids,omitempty"`
	TagFilter            map[string][]string `json:"tag_filter,omitempty"`
	Action               string              `json:"action,omitempty"`
	PortForwardingHost   string              `json:"port_forwarding_hosts,omitempty"`
	LocalPortForwardPort int                 `json:"local_portforward,omitempty"`
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
	Accounts   []Account      `json:"accounts,omitempty"`
	Principals []Principal    `json:"principals,omitempty"`
	Roles      []Role         `json:"iam_roles,omitempty"`
	Policies   []CommonPolicy `json:"iam_policies,omitempty"`
	SsmActions []SsmAction    `json:"ssm_actions,omitempty"`
}

func (v AccountRole) Parse() (roleType, accountId, name string, valid bool) {
	arn, err := arn.Parse(string(v))
	if err != nil {
		return "", "", "", false
	}
	if arn.Service != "iam" {
		return "", "", "", false
	}
	roleType, name, found := strings.Cut(arn.Resource, "/")
	if !found {
		return "", "", "", false
	}
	return roleType, name, "", true
}
