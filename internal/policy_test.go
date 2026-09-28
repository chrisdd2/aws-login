package internal

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestResolveInlinePoliciesBuiltinSsm(t *testing.T) {
	custom := `{"Version":"2012-10-17","Statement":[]}`
	in := map[string]string{
		"ssm":       "@builtin.ssm",
		"ssm-ws":    "  @builtin.ssm\n",
		"custom":    custom,
		"untouched": "not a builtin @builtin.ssm",
	}
	out, err := ResolveInlinePolicies(in)
	if err != nil {
		t.Fatal(err)
	}
	if out["custom"] != custom || out["untouched"] != in["untouched"] {
		t.Fatalf("non-builtin policies changed: %+v", out)
	}
	if in["ssm"] != "@builtin.ssm" {
		t.Fatal("input map was mutated")
	}
	for _, name := range []string{"ssm", "ssm-ws"} {
		doc := policyDocument{}
		if err := json.Unmarshal([]byte(out[name]), &doc); err != nil {
			t.Fatalf("%s: invalid json: %s", name, err)
		}
		actions := []string{}
		for _, s := range doc.Statement {
			if s.Effect != "Allow" {
				t.Fatalf("%s: unexpected effect %q", name, s.Effect)
			}
			actions = append(actions, s.Action...)
		}
		for _, want := range []string{"ssm:DescribeInstanceInformation", "ec2:DescribeInstances", "ec2:DescribeRegions", "ssm:StartSession", "ssm:TerminateSession"} {
			if !slices.Contains(actions, want) {
				t.Errorf("%s: missing action %s", name, want)
			}
		}
	}
}

func TestResolveInlinePoliciesUnknownBuiltin(t *testing.T) {
	if _, err := ResolveInlinePolicies(map[string]string{"x": "@builtin.nope"}); err == nil {
		t.Fatal("expected error for unknown builtin")
	}
}

func TestResolveInlinePoliciesEmpty(t *testing.T) {
	out, err := ResolveInlinePolicies(nil)
	if err != nil || len(out) != 0 {
		t.Fatalf("got %v %v", out, err)
	}
}

func boundaryStatements(t *testing.T, accountId string) map[string]policyStatement {
	t.Helper()
	doc := policyDocument{}
	if err := json.Unmarshal([]byte(boundaryPolicy(accountId)), &doc); err != nil {
		t.Fatalf("invalid json: %s", err)
	}
	bySid := map[string]policyStatement{}
	for _, s := range doc.Statement {
		bySid[s.Sid] = s
	}
	return bySid
}

func assertDeny(t *testing.T, s policyStatement, actions ...string) {
	t.Helper()
	if s.Effect != "Deny" {
		t.Fatalf("%s: effect %q, want Deny", s.Sid, s.Effect)
	}
	for _, a := range actions {
		if !slices.Contains(s.Action, a) {
			t.Errorf("%s: missing action %s", s.Sid, a)
		}
	}
}

func TestBoundaryPolicyProtectsItself(t *testing.T) {
	s := boundaryStatements(t, "111111111111")["DenyBoundaryPolicyModification"]
	assertDeny(t, s, "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:DeletePolicy")
	if !slices.Equal(s.Resource, []string{boundaryPolicyArn("111111111111")}) {
		t.Fatalf("resource %v, want boundary arn", s.Resource)
	}
}

func TestBoundaryPolicyDeniesModifyingUnboundedRoles(t *testing.T) {
	s := boundaryStatements(t, "111111111111")["DenyModifyUnboundedRoles"]
	assertDeny(t, s, "iam:UpdateAssumeRolePolicy", "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:UpdateRole")
	got := s.Condition["StringNotEqualsIfExists"]["iam:PermissionsBoundary"]
	if got != boundaryPolicyArn("111111111111") {
		t.Fatalf("condition %v, want StringNotEqualsIfExists on boundary arn", s.Condition)
	}
}

func TestBoundaryPolicyPassRoleLimitedToBoundedPath(t *testing.T) {
	statements := boundaryStatements(t, "111111111111")
	for _, s := range statements {
		if slices.Contains(s.Action, "iam:PassRole") {
			if _, ok := s.Condition["StringEquals"]["iam:PermissionsBoundary"]; ok {
				t.Fatalf("%s: iam:PassRole does not support iam:PermissionsBoundary", s.Sid)
			}
		}
	}
	s := statements["DenyPassRoleOutsideBoundedPath"]
	assertDeny(t, s, "iam:PassRole")
	if len(s.Resource) != 0 || !slices.Contains(s.NotResource, "arn:aws:iam::111111111111:role/aws-login-bounded/*") {
		t.Fatalf("resource %v notresource %v", s.Resource, s.NotResource)
	}
}

func TestBoundaryPolicyAssumeRoleLimitedToBoundedPathInAccount(t *testing.T) {
	s := boundaryStatements(t, "111111111111")["DenyAssumeRoleOutsideBoundedPath"]
	assertDeny(t, s, "sts:AssumeRole")
	if !slices.Equal(s.NotResource, []string{"arn:aws:iam::111111111111:role/aws-login-bounded/*"}) {
		t.Fatalf("notresource %v", s.NotResource)
	}
	if s.Condition["StringEquals"]["aws:ResourceAccount"] != "111111111111" {
		t.Fatalf("condition %v, want same-account only", s.Condition)
	}
}

func TestBoundaryPolicyFitsManagedPolicyLimit(t *testing.T) {
	if n := len(minimizePolicy(boundaryPolicy("111111111111"))); n > 6144 {
		t.Fatalf("boundary policy is %d characters, managed policy limit is 6144", n)
	}
}

func TestSsmPolicyOnlyManagesOwnSessions(t *testing.T) {
	doc := policyDocument{}
	if err := json.Unmarshal([]byte(ssmSessionPolicy()), &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range doc.Statement {
		if !slices.Contains(s.Action, "ssm:TerminateSession") {
			continue
		}
		if s.Condition["StringLike"]["ssm:resourceTag/aws:ssmmessages:session-id"] != "${aws:userid}*" {
			t.Fatalf("%s: terminate/resume not scoped to own sessions: %+v", s.Sid, s.Condition)
		}
		return
	}
	t.Fatal("no statement grants ssm:TerminateSession")
}
