package services

import (
	"github.com/chrisdd2/aws-login/internal"
)

type Config struct {
	Accounts     []internal.Account      `json:"accounts,omitempty"`
	Principals   []internal.Principal    `json:"principals,omitempty"`
	Roles        []internal.Role         `json:"iam_roles,omitempty"`
	Policies     []internal.CommonPolicy `json:"iam_policies,omitempty"`
	SsmInstances []internal.SsmInstance  `json:"ssm_instances,omitempty"`
}
