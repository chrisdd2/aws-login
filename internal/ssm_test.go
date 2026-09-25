package internal

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

type fakeSsm struct {
	input *ssm.DescribeInstanceInformationInput
	out   *ssm.DescribeInstanceInformationOutput
	err   error
}

func (f *fakeSsm) DescribeInstanceInformation(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	f.input = params
	return f.out, f.err
}

type fakeEc2 struct {
	inputs []*ec2.DescribeInstancesInput
	pages  []*ec2.DescribeInstancesOutput
	err    error
}

func (f *fakeEc2) DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error) {
	copied := *params
	f.inputs = append(f.inputs, &copied)
	if f.err != nil {
		return nil, f.err
	}
	out := f.pages[0]
	f.pages = f.pages[1:]
	return out, nil
}

func (f *fakeEc2) DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	return &ec2.DescribeRegionsOutput{}, nil
}

func ec2Instance(id string, name string) ec2Types.Instance {
	inst := ec2Types.Instance{InstanceId: aws.String(id)}
	if name != "" {
		inst.Tags = []ec2Types.Tag{{Key: aws.String("env"), Value: aws.String("x")}, {Key: aws.String("Name"), Value: aws.String(name)}}
	}
	return inst
}

func TestListSsmInstances(t *testing.T) {
	s := &fakeSsm{out: &ssm.DescribeInstanceInformationOutput{
		NextToken: aws.String("page-2"),
		InstanceInformationList: []ssmTypes.InstanceInformation{
			{InstanceId: aws.String("i-0000000000000000b"), ComputerName: aws.String("host-b"), IPAddress: aws.String("10.0.0.2"), PlatformName: aws.String("Amazon Linux")},
			{InstanceId: aws.String("i-0000000000000000a"), ComputerName: aws.String("host-a"), IPAddress: aws.String("10.0.0.1"), PlatformName: aws.String("Ubuntu")},
			{InstanceId: aws.String("i-0000000000000000c")},
		},
	}}
	e := &fakeEc2{pages: []*ec2.DescribeInstancesOutput{
		{
			NextToken:    aws.String("ec2-2"),
			Reservations: []ec2Types.Reservation{{Instances: []ec2Types.Instance{ec2Instance("i-0000000000000000a", "alpha")}}},
		},
		{
			Reservations: []ec2Types.Reservation{{Instances: []ec2Types.Instance{ec2Instance("i-0000000000000000b", "bravo"), ec2Instance("i-0000000000000000c", "")}}},
		},
	}}

	instances, next, err := ListSsmInstances(context.Background(), s, e, "page-1", 20)
	if err != nil {
		t.Fatal(err)
	}
	if next != "page-2" {
		t.Fatalf("next = %q", next)
	}
	if aws.ToString(s.input.NextToken) != "page-1" || aws.ToInt32(s.input.MaxResults) != 20 {
		t.Fatalf("unexpected ssm input %+v", s.input)
	}
	filters := map[string][]string{}
	for _, f := range s.input.Filters {
		filters[aws.ToString(f.Key)] = f.Values
	}
	if !slices.Equal(filters["ResourceType"], []string{"EC2Instance"}) || !slices.Equal(filters["PingStatus"], []string{"Online"}) {
		t.Fatalf("unexpected ssm filters %+v", filters)
	}

	if len(e.inputs) != 2 || aws.ToString(e.inputs[1].NextToken) != "ec2-2" {
		t.Fatalf("expected paged ec2 calls, got %d", len(e.inputs))
	}
	f := e.inputs[0].Filters
	if len(f) != 1 || aws.ToString(f[0].Name) != "instance-id" || len(f[0].Values) != 3 || e.inputs[0].InstanceIds != nil {
		t.Fatalf("unexpected ec2 filter %+v", e.inputs[0])
	}

	want := []SsmInstance{
		{Id: "i-0000000000000000b", Name: "bravo", ComputerName: "host-b", IpAddress: "10.0.0.2", Platform: "Amazon Linux"},
		{Id: "i-0000000000000000a", Name: "alpha", ComputerName: "host-a", IpAddress: "10.0.0.1", Platform: "Ubuntu"},
		{Id: "i-0000000000000000c"},
	}
	if !slices.Equal(instances, want) {
		t.Fatalf("got %+v\nwant %+v", instances, want)
	}
}

func TestListSsmInstancesEmptyPage(t *testing.T) {
	s := &fakeSsm{out: &ssm.DescribeInstanceInformationOutput{}}
	e := &fakeEc2{}
	instances, next, err := ListSsmInstances(context.Background(), s, e, "", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(instances) != 0 || next != "" || len(e.inputs) != 0 {
		t.Fatalf("expected empty result without ec2 call, got %v %q %d", instances, next, len(e.inputs))
	}
	if s.input.NextToken != nil {
		t.Fatalf("expected nil NextToken for first page")
	}
}

func TestListSsmInstancesErrors(t *testing.T) {
	if _, _, err := ListSsmInstances(context.Background(), &fakeSsm{err: errors.New("AccessDenied")}, &fakeEc2{}, "", 20); err == nil {
		t.Fatal("expected ssm error")
	}
	s := &fakeSsm{out: &ssm.DescribeInstanceInformationOutput{InstanceInformationList: []ssmTypes.InstanceInformation{{InstanceId: aws.String("i-0000000000000000a")}}}}
	if _, _, err := ListSsmInstances(context.Background(), s, &fakeEc2{err: errors.New("AccessDenied")}, "", 20); err == nil {
		t.Fatal("expected ec2 error")
	}
}

func TestSsmSessionUrl(t *testing.T) {
	got := SsmSessionUrl("eu-central-1", "i-0123456789abcdef0")
	want := "https://eu-central-1.console.aws.amazon.com/systems-manager/session-manager/i-0123456789abcdef0?region=eu-central-1"
	if got != want {
		t.Fatalf("got %q", got)
	}
}

func TestValidInstanceId(t *testing.T) {
	cases := map[string]bool{
		"i-0123456789abcdef0":      true,
		"i-01234567":               true,
		"i-0123":                   false,
		"mi-0123456789abcdef":      false,
		"i-0123456789ABCDEF0":      false,
		"i-0123456789abcdef0/../x": false,
		"":                         false,
	}
	for in, want := range cases {
		if got := ValidInstanceId.MatchString(in); got != want {
			t.Errorf("ValidInstanceId(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestValidSsmRegion(t *testing.T) {
	for _, r := range []string{DefaultSsmRegion, "us-east-1", "ap-southeast-4", "us-gov-west-1", "il-central-1", "mx-central-1"} {
		if !ValidSsmRegion(r) {
			t.Errorf("expected %q to be valid", r)
		}
	}
	for _, r := range []string{"", "evil.com", "eu-central-1.evil.com", "EU-CENTRAL-1", "eu-central", "eu-central-1/x", "eu-central-1?x"} {
		if ValidSsmRegion(r) {
			t.Errorf("expected %q to be invalid", r)
		}
	}
}

type fakeRegionsEc2 struct {
	fakeEc2
	input *ec2.DescribeRegionsInput
	out   *ec2.DescribeRegionsOutput
	err   error
}

func (f *fakeRegionsEc2) DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	f.input = params
	return f.out, f.err
}

func TestListEnabledRegions(t *testing.T) {
	e := &fakeRegionsEc2{out: &ec2.DescribeRegionsOutput{Regions: []ec2Types.Region{
		{RegionName: aws.String("us-east-1")},
		{RegionName: aws.String("eu-central-1")},
		{RegionName: aws.String("bogus.region")},
		{RegionName: aws.String("ap-southeast-2")},
	}}}
	regions, err := ListEnabledRegions(context.Background(), e)
	if err != nil {
		t.Fatal(err)
	}
	if aws.ToBool(e.input.AllRegions) {
		t.Fatal("expected only enabled regions to be requested")
	}
	if want := []string{"ap-southeast-2", "eu-central-1", "us-east-1"}; !slices.Equal(regions, want) {
		t.Fatalf("got %v, want %v", regions, want)
	}
	if _, err := ListEnabledRegions(context.Background(), &fakeRegionsEc2{err: errors.New("AccessDenied")}); err == nil {
		t.Fatal("expected error")
	}
}
