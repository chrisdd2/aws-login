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
