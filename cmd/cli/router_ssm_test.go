package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	stsTypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/chrisdd2/aws-login/internal"
)

type fakeSts struct {
	roleArns []string
}

func (f *fakeSts) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	f.roleArns = append(f.roleArns, aws.ToString(params.RoleArn))
	return &sts.AssumeRoleOutput{Credentials: &stsTypes.Credentials{
		AccessKeyId:     aws.String("AKIA"),
		SecretAccessKey: aws.String("secret"),
		SessionToken:    aws.String("token"),
	}}, nil
}

type fakeSsmClient struct {
	nextTokens []string
	err        error
}

func (f *fakeSsmClient) DescribeInstanceInformation(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	f.nextTokens = append(f.nextTokens, aws.ToString(params.NextToken))
	if f.err != nil {
		return nil, f.err
	}
	return &ssm.DescribeInstanceInformationOutput{
		NextToken: aws.String("more"),
		InstanceInformationList: []ssmTypes.InstanceInformation{
			{InstanceId: aws.String("i-0123456789abcdef0"), ComputerName: aws.String("web-1"), IPAddress: aws.String("10.0.0.5"), PlatformName: aws.String("Ubuntu")},
		},
	}, nil
}

type fakeEc2Client struct {
	regions   []string
	regionErr error
}

func (f fakeEc2Client) DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	if f.regionErr != nil {
		return nil, f.regionErr
	}
	out := &ec2.DescribeRegionsOutput{}
	for _, r := range f.regions {
		out.Regions = append(out.Regions, ec2Types.Region{RegionName: aws.String(r)})
	}
	return out, nil
}

func (fakeEc2Client) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	return &ec2.DescribeInstancesOutput{Reservations: []ec2Types.Reservation{{Instances: []ec2Types.Instance{{
		InstanceId: aws.String("i-0123456789abcdef0"),
		Tags:       []ec2Types.Tag{{Key: aws.String("Name"), Value: aws.String("web")}},
	}}}}}, nil
}

type ssmHarness struct {
	sts     *fakeSts
	ssm     *fakeSsmClient
	ec2     fakeEc2Client
	regions []string
	creds   []internal.AwsCredentials
	handler http.Handler
}

func newSsmHarness(t *testing.T) *ssmHarness {
	t.Helper()
	h := &ssmHarness{sts: &fakeSts{}, ssm: &fakeSsmClient{}}
	h.handler = testRouterWith(t, h.sts, func(creds internal.AwsCredentials, region string) (internal.SsmClient, internal.Ec2Client) {
		h.regions = append(h.regions, region)
		h.creds = append(h.creds, creds)
		return h.ssm, h.ec2
	})
	return h
}

func decodeRegions(t *testing.T, rec *httptest.ResponseRecorder) (regions []string, def string) {
	t.Helper()
	resp := struct {
		Regions []string `json:"regions"`
		Default string   `json:"default"`
	}{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	return resp.Regions, resp.Default
}

func TestSsmRegions(t *testing.T) {
	h := newSsmHarness(t)
	h.ec2.regions = []string{"us-east-1", "eu-central-1", "eu-west-1"}
	rec := h.get(t, "/role/333333333333/ops/ssm/regions", "devs")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	regions, def := decodeRegions(t, rec)
	if !slices.Equal(regions, []string{"eu-central-1", "eu-west-1", "us-east-1"}) || def != "eu-central-1" {
		t.Fatalf("regions %v default %q", regions, def)
	}
	if len(h.sts.roleArns) != 1 || h.sts.roleArns[0] != internal.RoleArn("333333333333", "ops") {
		t.Fatalf("assumed %v", h.sts.roleArns)
	}
}

func TestSsmRegionsDefaultFallsBackToFirst(t *testing.T) {
	h := newSsmHarness(t)
	h.ec2.regions = []string{"us-west-2", "ap-south-1"}
	regions, def := decodeRegions(t, h.get(t, "/role/333333333333/ops/ssm/regions", "devs"))
	if def != "ap-south-1" || len(regions) != 2 {
		t.Fatalf("regions %v default %q", regions, def)
	}
}

func TestSsmRegionsAwsError(t *testing.T) {
	h := newSsmHarness(t)
	h.ec2.regionErr = errors.New(`UnauthorizedOperation: not authorized to perform "ec2:DescribeRegions"`)
	rec := h.get(t, "/role/333333333333/ops/ssm/regions", "devs")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	resp := struct {
		Error string `json:"error"`
	}{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil || !strings.Contains(resp.Error, `"ec2:DescribeRegions"`) {
		t.Fatalf("unexpected error body %q %v", resp.Error, err)
	}
}

func (h *ssmHarness) get(t *testing.T, path string, groups ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(sessionCookie(t, groups...))
	rec := httptest.NewRecorder()
	h.handler.ServeHTTP(rec, req)
	return rec
}

func TestSsmInstancesDefaultRegion(t *testing.T) {
	h := newSsmHarness(t)
	rec := h.get(t, "/role/333333333333/ops/ssm/instances", "devs")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	resp := struct {
		Region    string                 `json:"region"`
		Instances []internal.SsmInstance `json:"instances"`
		Next      string                 `json:"next"`
	}{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Region != "eu-central-1" || resp.Next != "more" || len(resp.Instances) != 1 {
		t.Fatalf("unexpected response %+v", resp)
	}
	if got := resp.Instances[0]; got.Id != "i-0123456789abcdef0" || got.Name != "web" || got.ComputerName != "web-1" {
		t.Fatalf("unexpected instance %+v", got)
	}
	if len(h.regions) != 1 || h.regions[0] != "eu-central-1" {
		t.Fatalf("factory regions %v", h.regions)
	}
	if len(h.sts.roleArns) != 1 || h.sts.roleArns[0] != internal.RoleArn("333333333333", "ops") {
		t.Fatalf("assumed %v", h.sts.roleArns)
	}
	if h.creds[0].AccessKeyId != "AKIA" || h.creds[0].SessionToken != "token" {
		t.Fatalf("factory creds %+v", h.creds[0])
	}
}

func TestSsmInstancesRegionAndNext(t *testing.T) {
	h := newSsmHarness(t)
	rec := h.get(t, "/role/333333333333/ops/ssm/instances?region=us-west-2&next=abc", "devs")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	if h.regions[0] != "us-west-2" || h.ssm.nextTokens[0] != "abc" {
		t.Fatalf("regions %v next %v", h.regions, h.ssm.nextTokens)
	}
}

func TestSsmRejections(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		groups []string
		status int
	}{
		{"instances bad region", "/role/333333333333/ops/ssm/instances?region=evil.com", []string{"devs"}, http.StatusBadRequest},
		{"session bad region", "/role/333333333333/ops/ssm/i-0123456789abcdef0?region=evil.com", []string{"devs"}, http.StatusBadRequest},
		{"instances ssm disabled", "/role/111111111111/dev/ssm/instances", []string{"devs"}, http.StatusNotFound},
		{"session ssm disabled", "/role/111111111111/dev/ssm/i-0123456789abcdef0", []string{"devs"}, http.StatusNotFound},
		{"regions ssm disabled", "/role/111111111111/dev/ssm/regions", []string{"devs"}, http.StatusNotFound},
		{"regions no role access", "/role/444444444444/ops-admin/ssm/regions", []string{"devs"}, http.StatusUnauthorized},
		{"instances no role access", "/role/444444444444/ops-admin/ssm/instances", []string{"devs"}, http.StatusUnauthorized},
		{"session no role access", "/role/444444444444/ops-admin/ssm/i-0123456789abcdef0", []string{"devs"}, http.StatusUnauthorized},
		{"session bad instance id", "/role/333333333333/ops/ssm/not-an-instance", []string{"devs"}, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newSsmHarness(t)
			rec := h.get(t, c.path, c.groups...)
			if rec.Code != c.status {
				t.Fatalf("status %d, want %d, body %s", rec.Code, c.status, rec.Body.String())
			}
			if len(h.sts.roleArns) != 0 || len(h.regions) != 0 {
				t.Fatalf("no aws calls expected, got sts %v regions %v", h.sts.roleArns, h.regions)
			}
		})
	}
}

func TestSsmInstancesAwsErrorIsJson(t *testing.T) {
	h := newSsmHarness(t)
	h.ssm.err = errors.New(`AccessDeniedException: User: "arn:aws:sts::333333333333:assumed-role/ops/alice" is not authorized`)
	rec := h.get(t, "/role/333333333333/ops/ssm/instances", "devs")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status %d", rec.Code)
	}
	resp := struct {
		Error string `json:"error"`
	}{}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("error body is not valid json: %s", err)
	}
	if !strings.Contains(resp.Error, `"arn:aws:sts::333333333333:assumed-role/ops/alice"`) {
		t.Fatalf("unexpected error %q", resp.Error)
	}
}

func TestIndexSsmButtonOnlyForEnabledRoles(t *testing.T) {
	h := newSsmHarness(t)
	rec := h.get(t, "/", "devs")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `data-ssm="/role/333333333333/ops/ssm"`) {
		t.Fatal("expected ssm button for ops")
	}
	if strings.Contains(body, `data-ssm="/role/111111111111/dev/ssm"`) {
		t.Fatal("unexpected ssm button for dev")
	}
}

func TestExampleConfigSsmRole(t *testing.T) {
	roles, err := loadConfig("../../example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var found *internal.Role
	for i := range roles {
		if roles[i].Name == "ssm-operator" {
			found = &roles[i]
		}
	}
	if found == nil || !found.SsmEnabled {
		t.Fatalf("expected ssm-operator role with ssm_enabled, got %+v", roles)
	}
	if found.Policies["ssm-session"] != "@builtin.ssm" {
		t.Fatalf("expected builtin reference, got %q", found.Policies["ssm-session"])
	}
	resolved, err := internal.ResolveInlinePolicies(found.Policies)
	if err != nil {
		t.Fatal(err)
	}
	policy := map[string]any{}
	if err := json.Unmarshal([]byte(resolved["ssm-session"]), &policy); err != nil {
		t.Fatalf("resolved ssm-session policy is not valid json: %s", err)
	}
}
