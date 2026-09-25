package internal

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2Types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmTypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

const DefaultSsmRegion = "eu-central-1"

var ValidInstanceId = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)

var validRegion = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]{1,2}$`)

func ValidSsmRegion(r string) bool {
	return validRegion.MatchString(r)
}

func ListEnabledRegions(ctx context.Context, ec2Cl Ec2Client) ([]string, error) {
	resp, err := ec2Cl.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)})
	if err != nil {
		return nil, WrapError(err, "ec2.DescribeRegions")
	}
	regions := make([]string, 0, len(resp.Regions))
	for _, r := range resp.Regions {
		if name := aws.ToString(r.RegionName); ValidSsmRegion(name) {
			regions = append(regions, name)
		}
	}
	slices.Sort(regions)
	return regions, nil
}

type SsmClient interface {
	DescribeInstanceInformation(ctx context.Context, params *ssm.DescribeInstanceInformationInput, optFns ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error)
}

type Ec2Client interface {
	DescribeInstances(ctx context.Context, params *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

type SsmInstance struct {
	Id           string `json:"id"`
	Name         string `json:"name"`
	ComputerName string `json:"computerName"`
	IpAddress    string `json:"ipAddress"`
	Platform     string `json:"platform"`
}

func NewSsmClients(creds AwsCredentials, region string) (SsmClient, Ec2Client) {
	provider := credentials.NewStaticCredentialsProvider(creds.AccessKeyId, creds.SecretAccessKey, creds.SessionToken)
	return ssm.New(ssm.Options{Region: region, Credentials: provider}),
		ec2.New(ec2.Options{Region: region, Credentials: provider})
}

func ListSsmInstances(ctx context.Context, ssmCl SsmClient, ec2Cl Ec2Client, nextToken string, pageSize int32) ([]SsmInstance, string, error) {
	input := &ssm.DescribeInstanceInformationInput{
		MaxResults: aws.Int32(pageSize),
		Filters: []ssmTypes.InstanceInformationStringFilter{
			{Key: aws.String("ResourceType"), Values: []string{"EC2Instance"}},
			{Key: aws.String("PingStatus"), Values: []string{"Online"}},
		},
	}
	if nextToken != "" {
		input.NextToken = aws.String(nextToken)
	}
	resp, err := ssmCl.DescribeInstanceInformation(ctx, input)
	if err != nil {
		return nil, "", WrapError(err, "ssm.DescribeInstanceInformation")
	}

	instances := make([]SsmInstance, 0, len(resp.InstanceInformationList))
	ids := make([]string, 0, len(resp.InstanceInformationList))
	for _, info := range resp.InstanceInformationList {
		id := aws.ToString(info.InstanceId)
		ids = append(ids, id)
		instances = append(instances, SsmInstance{
			Id:           id,
			ComputerName: aws.ToString(info.ComputerName),
			IpAddress:    aws.ToString(info.IPAddress),
			Platform:     aws.ToString(info.PlatformName),
		})
	}

	if len(ids) > 0 {
		names := map[string]string{}
		ec2Input := &ec2.DescribeInstancesInput{
			Filters: []ec2Types.Filter{{Name: aws.String("instance-id"), Values: ids}},
		}
		for {
			ec2Resp, err := ec2Cl.DescribeInstances(ctx, ec2Input)
			if err != nil {
				return nil, "", WrapError(err, "ec2.DescribeInstances")
			}
			for _, res := range ec2Resp.Reservations {
				for _, inst := range res.Instances {
					for _, t := range inst.Tags {
						if aws.ToString(t.Key) == "Name" {
							names[aws.ToString(inst.InstanceId)] = aws.ToString(t.Value)
						}
					}
				}
			}
			if aws.ToString(ec2Resp.NextToken) == "" {
				break
			}
			ec2Input.NextToken = ec2Resp.NextToken
		}
		for i := range instances {
			instances[i].Name = names[instances[i].Id]
		}
	}

	Debugf("ListSsmInstances: %d instances, next=%q", len(instances), aws.ToString(resp.NextToken))
	return instances, aws.ToString(resp.NextToken), nil
}

func SsmSessionUrl(region string, instanceId string) string {
	return fmt.Sprintf("https://%s.console.aws.amazon.com/systems-manager/session-manager/%s?region=%s",
		region, url.PathEscape(instanceId), url.QueryEscape(region))
}
