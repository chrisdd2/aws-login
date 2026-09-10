package internal

import (
	"time"
)

type Role struct {
	Name               string            `json:"name,omitempty" sql:"unique"`
	AccountId          string            `json:"account_id,omitempty"`
	ManagedPolicies    []string          `json:"managed_policies,omitempty"`
	MaxSessionDuration time.Duration     `json:"max_session_duration,omitempty"`
	Policies           map[string]string `json:"policies,omitempty"`
	Tags               map[string]string `json:"tags,omitempty"`
	Claim              []string          `json:"claim,omitempty"`
	NoIamBoundary      bool              `json:"no_boundary,omitempty"`
}
