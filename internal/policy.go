package internal

import (
	"encoding/json"
	"fmt"
	"strings"
)

// policyDocument/policyStatement model just enough of the IAM policy grammar
// for the documents this package generates, so they can be built as data and
// marshaled instead of hand-templated as JSON strings.
type policyDocument struct {
	Version   string            `json:"Version"`
	Statement []policyStatement `json:"Statement"`
}

type policyStatement struct {
	Sid       string                    `json:"Sid,omitempty"`
	Effect    string                    `json:"Effect"`
	Action    []string                  `json:"Action"`
	Resource  []string                  `json:"Resource,omitempty"`
	Principal map[string]string         `json:"Principal,omitempty"`
	Condition map[string]map[string]any `json:"Condition,omitempty"`
}

// marshalPolicy renders a policy document to JSON. The statements are always
// built in-process from static/known-good data, so a marshal error here
// indicates a programming error, not a runtime condition callers can recover
// from.
func marshalPolicy(statements ...policyStatement) string {
	buf, err := json.Marshal(policyDocument{Version: "2012-10-17", Statement: statements})
	if err != nil {
		panic(fmt.Sprintf("marshalPolicy: %s", err))
	}
	return string(buf)
}

func boundaryPolicy(permissionBoundaryArn, bootstrapRoleArn string) string {
	notBoundedCondition := map[string]map[string]any{
		"StringNotEqualsIfExists": {"iam:PermissionsBoundary": permissionBoundaryArn},
	}
	return marshalPolicy(
		policyStatement{
			Sid:      "AllowEverythingElse",
			Effect:   "Allow",
			Action:   []string{"*"},
			Resource: []string{"*"},
		},
		policyStatement{
			Sid:    "DenyAllIAMUserActions",
			Effect: "Deny",
			Action: []string{
				"iam:CreateUser",
				"iam:DeleteUser",
				"iam:CreateAccessKey",
				"iam:CreateLoginProfile",
				"iam:UpdateLoginProfile",
				"iam:AttachUserPolicy",
				"iam:DetachUserPolicy",
				"iam:PutUserPolicy",
				"iam:DeleteUserPolicy",
			},
			Resource: []string{"*"},
		},
		policyStatement{
			Sid:    "DenyAllIAMGroupActions",
			Effect: "Deny",
			Action: []string{
				"iam:CreateGroup",
				"iam:DeleteGroup",
				"iam:AddUserToGroup",
				"iam:RemoveUserFromGroup",
				"iam:AttachGroupPolicy",
				"iam:DetachGroupPolicy",
				"iam:PutGroupPolicy",
				"iam:DeleteGroupPolicy",
			},
			Resource: []string{"*"},
		},
		policyStatement{
			Sid:       "DenyCreateRoleWithoutBoundary",
			Effect:    "Deny",
			Action:    []string{"iam:CreateRole"},
			Resource:  []string{"*"},
			Condition: notBoundedCondition,
		},
		policyStatement{
			Sid:       "DenyUpdateRoleToRemoveBoundary",
			Effect:    "Deny",
			Action:    []string{"iam:UpdateRole"},
			Resource:  []string{"*"},
			Condition: notBoundedCondition,
		},
		policyStatement{
			Sid:    "DenyBoundaryActions",
			Effect: "Deny",
			Action: []string{
				"iam:DeleteRolePermissionsBoundary",
				"iam:PutRolePermissionsBoundary",
				"iam:DeleteUserPermissionsBoundary",
				"iam:PutUserPermissionsBoundary",
			},
			Resource: []string{"*"},
		},
		policyStatement{
			Sid:    "DenyManagementRoleModification",
			Effect: "Deny",
			Action: []string{
				"iam:CreateRole",
				"iam:DeleteRole",
				"iam:UpdateRole",
				"iam:UpdateAssumeRolePolicy",
				"iam:PutRolePolicy",
				"iam:DeleteRolePolicy",
				"iam:AttachRolePolicy",
				"iam:DetachRolePolicy",
				"iam:TagRole",
				"iam:UntagRole",
			},
			Resource: []string{bootstrapRoleArn},
		},
		policyStatement{
			Sid:      "DenyPassRoleToService",
			Effect:   "Deny",
			Action:   []string{"iam:PassRole"},
			Resource: []string{bootstrapRoleArn},
			Condition: map[string]map[string]any{
				"StringLike": {"iam:PassedToService": "*"},
			},
		},
		policyStatement{
			Sid:      "DenyPassRoleOfBoundedRoles",
			Effect:   "Deny",
			Action:   []string{"iam:PassRole"},
			Resource: []string{"*"},
			Condition: map[string]map[string]any{
				"StringEquals": {"iam:PermissionsBoundary": permissionBoundaryArn},
			},
		},
	)
}

func trustPolicy(arn string) string {
	return marshalPolicy(policyStatement{
		Effect:    "Allow",
		Principal: map[string]string{"AWS": arn},
		Action:    []string{"sts:AssumeRole"},
	})
}

const builtinPolicyPrefix = "@builtin."

func ssmSessionPolicy() string {
	return marshalPolicy(
		policyStatement{
			Sid:    "ListInstances",
			Effect: "Allow",
			Action: []string{
				"ssm:DescribeInstanceInformation",
				"ssm:DescribeInstanceProperties",
				"ssm:DescribeSessions",
				"ssm:GetConnectionStatus",
				"ec2:DescribeInstances",
				"ec2:DescribeRegions",
			},
			Resource: []string{"*"},
		},
		policyStatement{
			Sid:    "StartSession",
			Effect: "Allow",
			Action: []string{"ssm:StartSession"},
			Resource: []string{
				"arn:aws:ec2:*:*:instance/*",
				"arn:aws:ssm:*:*:document/SSM-SessionManagerRunShell",
			},
		},
		policyStatement{
			Sid:      "ManageOwnSessions",
			Effect:   "Allow",
			Action:   []string{"ssm:TerminateSession", "ssm:ResumeSession"},
			Resource: []string{"arn:aws:ssm:*:*:session/*"},
		},
	)
}

var builtinPolicies = map[string]func() string{
	"ssm": ssmSessionPolicy,
}

func ResolveInlinePolicies(policies map[string]string) (map[string]string, error) {
	if len(policies) == 0 {
		return policies, nil
	}
	resolved := make(map[string]string, len(policies))
	for name, document := range policies {
		value := strings.TrimSpace(document)
		if builtinName, ok := strings.CutPrefix(value, builtinPolicyPrefix); ok {
			builtin, found := builtinPolicies[builtinName]
			if !found {
				return nil, fmt.Errorf("policy %q: unknown builtin %q", name, value)
			}
			document = builtin()
		}
		resolved[name] = document
	}
	return resolved, nil
}

func minimizePolicy(policy string) string {
	lines := []string{}
	for line := range strings.SplitSeq(policy, "\n") {
		lines = append(lines, strings.TrimSpace(line))
	}
	return strings.Join(lines, "")
}
