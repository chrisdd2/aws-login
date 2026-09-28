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
	Sid         string                    `json:"Sid,omitempty"`
	Effect      string                    `json:"Effect"`
	Action      []string                  `json:"Action"`
	Resource    []string                  `json:"Resource,omitempty"`
	NotResource []string                  `json:"NotResource,omitempty"`
	Principal   map[string]string         `json:"Principal,omitempty"`
	Condition   map[string]map[string]any `json:"Condition,omitempty"`
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

const BoundedRolePath = "/aws-login-bounded/"

func boundaryPolicy(accountId string) string {
	permissionBoundaryArn := boundaryPolicyArn(accountId)
	bootstrapRoleArn := BootstrapRoleArn(accountId)
	notBoundedCondition := map[string]map[string]any{
		"StringNotEqualsIfExists": {"iam:PermissionsBoundary": permissionBoundaryArn},
	}
	boundedRoles := fmt.Sprintf("arn:aws:iam::%s:role%s*", accountId, BoundedRolePath)
	serviceLinkedRoles := fmt.Sprintf("arn:aws:iam::%s:role/aws-service-role/*", accountId)
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
			Sid:    "DenyModifyUnboundedRoles",
			Effect: "Deny",
			Action: []string{
				"iam:UpdateRole",
				"iam:UpdateRoleDescription",
				"iam:UpdateAssumeRolePolicy",
				"iam:PutRolePolicy",
				"iam:DeleteRolePolicy",
				"iam:AttachRolePolicy",
				"iam:DetachRolePolicy",
				"iam:DeleteRole",
			},
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
			Sid:    "DenyBoundaryPolicyModification",
			Effect: "Deny",
			Action: []string{
				"iam:CreatePolicyVersion",
				"iam:DeletePolicyVersion",
				"iam:SetDefaultPolicyVersion",
				"iam:DeletePolicy",
				"iam:TagPolicy",
				"iam:UntagPolicy",
			},
			Resource: []string{permissionBoundaryArn},
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
			Sid:         "DenyPassRoleOutsideBoundedPath",
			Effect:      "Deny",
			Action:      []string{"iam:PassRole"},
			NotResource: []string{boundedRoles, serviceLinkedRoles},
		},
		policyStatement{
			Sid:         "DenyAssumeRoleOutsideBoundedPath",
			Effect:      "Deny",
			Action:      []string{"sts:AssumeRole"},
			NotResource: []string{boundedRoles},
			Condition: map[string]map[string]any{
				"StringEquals": {"aws:ResourceAccount": accountId},
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

func minimizePolicy(policy string) string {
	lines := []string{}
	for line := range strings.SplitSeq(policy, "\n") {
		lines = append(lines, strings.TrimSpace(line))
	}
	return strings.Join(lines, "")
}
