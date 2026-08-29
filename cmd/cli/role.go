package main

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/chrisdd2/aws-login/internal"
	"golang.org/x/sync/errgroup"
)

type RoleOptions struct {
	RoleName           string
	Description        string
	MaxSessionDuration time.Duration
	InlinePolicies     map[string]string
	ManagedPolicies    []string
	Tags               map[string]string
	AssumeRoleDocument string
	PermissionBoundary string
}

const uniqSuffix = "fea85e636e374e9bfb9488817817674"

var (
	bootstrapRoleName      = shortRoleName("aws-login-bootstrap")
	permissionBoundaryName = shortRoleName("aws-login-iam-boundary")
)

var defaultTags = map[string]string{
	"aws-login": "true",
}

func SyncRole(ctx context.Context, iamSvc *iam.Client, opts *RoleOptions) error {
	// check if role exists
	resp, err := iamSvc.GetRole(ctx, &iam.GetRoleInput{RoleName: &opts.RoleName})
	if err != nil {
		var notExistError *iamTypes.NoSuchEntityException
		if errors.As(err, &notExistError) {
			// role doesn't exist
			return createRole(ctx, iamSvc, opts)
		}
		var alreadyExists *iamTypes.EntityAlreadyExistsException
		if !errors.As(err, &alreadyExists) {
			return err
		}
	}
	// check if the basic stuff of the role need update
	if opts.Description != aws.ToString(resp.Role.Description) || int32(opts.MaxSessionDuration.Seconds()) != aws.ToInt32(resp.Role.MaxSessionDuration) {
		_, err := iamSvc.UpdateRole(ctx, &iam.UpdateRoleInput{RoleName: resp.Role.RoleName, Description: &opts.Description, MaxSessionDuration: durationToAwsTime(opts.MaxSessionDuration)})
		if err != nil {
			return err
		}
	}

	if resp.Role.PermissionsBoundary != nil {
		if _, err := iamSvc.DeleteRolePermissionsBoundary(ctx, &iam.DeleteRolePermissionsBoundaryInput{RoleName: resp.Role.RoleName}); err != nil {
			return err
		}
	}
	if opts.PermissionBoundary != "" {
		if _, err := iamSvc.PutRolePermissionsBoundary(ctx, &iam.PutRolePermissionsBoundaryInput{PermissionsBoundary: &opts.PermissionBoundary, RoleName: resp.Role.RoleName}); err != nil {
			return err
		}
	}

	if opts.AssumeRoleDocument != aws.ToString(resp.Role.AssumeRolePolicyDocument) {
		_, err := iamSvc.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{PolicyDocument: &opts.AssumeRoleDocument, RoleName: resp.Role.RoleName})
		if err != nil {
			return err
		}
	}
	// update tags, no reason to check
	_, err = iamSvc.TagRole(ctx, &iam.TagRoleInput{RoleName: resp.Role.RoleName, Tags: mapToAwsTags(opts.Tags)})
	if err != nil {
		return err
	}

	// managed policies
	managedPolicyPaginator := iam.NewListAttachedRolePoliciesPaginator(iamSvc, &iam.ListAttachedRolePoliciesInput{RoleName: resp.Role.RoleName})
	// to remove
	managedPolicyToIgnore := []string{}
	managedPolicyToRemove := []string{}
	for managedPolicyPaginator.HasMorePages() {
		policies, err := managedPolicyPaginator.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, p := range policies.AttachedPolicies {
			arn := aws.ToString(p.PolicyArn)
			if slices.Contains(opts.ManagedPolicies, arn) {
				managedPolicyToIgnore = append(managedPolicyToIgnore, arn)
				continue
			}
			managedPolicyToRemove = append(managedPolicyToRemove, arn)
		}
	}
	for _, p := range managedPolicyToRemove {
		_, err := iamSvc.DetachRolePolicy(ctx, &iam.DetachRolePolicyInput{RoleName: resp.Role.RoleName, PolicyArn: &p})
		if err != nil {
			return err
		}
	}
	for _, p := range opts.ManagedPolicies {
		if slices.Contains(managedPolicyToIgnore, p) {
			continue
		}
		_, err := iamSvc.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{RoleName: resp.Role.RoleName, PolicyArn: &p})
		if err != nil {
			return err
		}
	}

	policiesToRemove := []string{}
	// inline policies
	policiesPaginator := iam.NewListRolePoliciesPaginator(iamSvc, &iam.ListRolePoliciesInput{RoleName: resp.Role.RoleName})
	for policiesPaginator.HasMorePages() {
		policies, err := policiesPaginator.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, p := range policies.PolicyNames {
			_, found := opts.InlinePolicies[p]
			if found {
				continue
			}
			policiesToRemove = append(policiesToRemove, p)
		}
	}
	for _, p := range policiesToRemove {
		_, err := iamSvc.DeleteRolePolicy(ctx, &iam.DeleteRolePolicyInput{PolicyName: &p, RoleName: resp.Role.RoleName})
		if err != nil {
			return err
		}
	}
	for name, document := range opts.InlinePolicies {
		_, err := iamSvc.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			PolicyDocument: &document,
			PolicyName:     &name,
			RoleName:       &opts.RoleName,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func createRole(ctx context.Context, iamSvc *iam.Client, opts *RoleOptions) error {
	_, err := iamSvc.CreateRole(ctx, &iam.CreateRoleInput{
		AssumeRolePolicyDocument: &opts.AssumeRoleDocument,
		RoleName:                 &opts.RoleName,
		Description:              &opts.Description,
		MaxSessionDuration:       durationToAwsTime(opts.MaxSessionDuration),
		Tags:                     mapToAwsTags(opts.Tags),
	})
	if err != nil {
		return err
	}
	for _, p := range opts.ManagedPolicies {
		_, err := iamSvc.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{PolicyArn: &p, RoleName: &opts.RoleName})
		if err != nil {
			return err
		}
	}
	for name, document := range opts.InlinePolicies {
		_, err := iamSvc.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			PolicyDocument: &document,
			PolicyName:     &name,
			RoleName:       &opts.RoleName,
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func CreateBootstrapRole(ctx context.Context, iamSvc *iam.Client, principalArn string) error {
	return SyncRole(ctx, iamSvc, &RoleOptions{
		RoleName:           bootstrapRoleName,
		Description:        "bootstrap role for aws-login application",
		MaxSessionDuration: time.Hour,
		Tags:               map[string]string{"aws-login:role": "bootstrap"},
		InlinePolicies: map[string]string{
			"iam": `{
					"Version": "2012-10-17",
					"Statement": [{
						"Effect": "Allow",
						"Action": "iam:*",
						"Resource": "*"
					}]
				}`,
		},
		AssumeRoleDocument: trustPolicy(principalArn),
	})
}

type resolvedAccount struct {
	Name      string
	AccountId string
	Roles     []RoleOptions
}

func SyncAllAccounts(ctx context.Context, stsSvc *sts.Client, cfg *internal.RuntimeConfig) error {
	whoami, err := stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return err
	}

	bootstrapTrustPolicy := trustPolicy(*whoami.Arn)

	roleMap := map[string]internal.Role{}
	for _, r := range cfg.Roles {
		roleMap[r.Name] = r
	}

	policyMap := map[string]internal.CommonPolicy{}
	for _, p := range cfg.Policies {
		policyMap[p.Name] = p
	}

	ssmMap := map[string]internal.SsmAction{}
	for _, a := range cfg.SsmActions {
		ssmMap[a.Name] = a
	}

	accounts := []resolvedAccount{}
	for _, acc := range cfg.Accounts {
		roles := []RoleOptions{}
		for _, r := range acc.Roles {
			roleType, _, roleName, valid := r.Parse()
			if !valid {
				continue
			}
			switch roleType {
			case "iam":
				role, ok := roleMap[roleName]
				if !ok {
					continue
				}
				managedPolicies := []string{}
				policies := map[string]string{}
				for _, p := range role.Policies {
					policyName, valid := strings.CutPrefix(p, "@inline:")
					if valid {
						policies[policyName] = policyMap[policyName].Text
					} else {
						managedPolicies = append(managedPolicies, p)
					}
				}
				roles = append(roles, RoleOptions{
					RoleName:           roleName,
					Description:        "aws-login role",
					MaxSessionDuration: role.MaxSessionDuration,
					InlinePolicies:     policies,
					ManagedPolicies:    managedPolicies,
					AssumeRoleDocument: bootstrapTrustPolicy,
				})
			case "ssm":
				ssmAction, ok := ssmMap[roleName]
				if !ok {
					continue
				}
				policy, err := ssmPolicy(ssmAction, acc.AwsAccountId)
				if err != nil {
					log.Printf("skipping [%s]: [%s]\n", roleName, err)
					continue
				}
				roles = append(roles, RoleOptions{
					RoleName:           roleName,
					Description:        "aws-login ssm role",
					MaxSessionDuration: time.Hour * 8,
					InlinePolicies: map[string]string{
						"Ssm": policy,
					},
					AssumeRoleDocument: bootstrapTrustPolicy,
				})

			}
		}

		accounts = append(accounts, resolvedAccount{
			Name:      acc.Name,
			AccountId: acc.AwsAccountId,
			Roles:     roles,
		})
	}
	eg := errgroup.Group{}

	for _, acc := range accounts {
		eg.Go(func() error {
			return SyncAccount(ctx, stsSvc, &acc)
		})
	}
	return eg.Wait()
}

func upsertPermissionBoundary(ctx context.Context, iamSvc *iam.Client, bootstrapRoleArn, permissionBoundaryArn string) error {
	expectedPolicyDocument := boundaryPolicy(permissionBoundaryArn, bootstrapRoleArn)

	policyResp, err := iamSvc.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &permissionBoundaryArn})
	if err != nil {
		var notExistError *iamTypes.NoSuchEntityException
		if errors.As(err, &notExistError) {
			// role doesn't exist
			_, err := iamSvc.CreatePolicy(ctx, &iam.CreatePolicyInput{PolicyDocument: &expectedPolicyDocument, PolicyName: &permissionBoundaryName, Description: aws.String("aws-login iam boundary"), Tags: mapToAwsTags(nil)})
			return err
		}
		var alreadyExists *iamTypes.EntityAlreadyExistsException
		if !errors.As(err, &alreadyExists) {
			return err
		}
	}
	// make sure the document is the same

	resp, err := iamSvc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policyResp.Policy.Arn, VersionId: policyResp.Policy.DefaultVersionId})
	if err != nil {
		return err
	}
	if aws.ToString(resp.PolicyVersion.Document) != expectedPolicyDocument {
		// put ours
		if _, err := iamSvc.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{PolicyArn: policyResp.Policy.Arn, PolicyDocument: &expectedPolicyDocument, SetAsDefault: true}); err != nil {
			return err
		}
	}
	return nil
}

func SyncAccount(ctx context.Context, stsSvc *sts.Client, acc *resolvedAccount) error {
	bootstrapRole := bootstrapRoleArn(acc.AccountId)
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithCredentialsProvider(
			stscreds.NewAssumeRoleProvider(stsSvc, bootstrapRole),
		),
	)
	if err != nil {
		return err
	}
	iamSvc := iam.NewFromConfig(cfg)
	// make sure permission boundary exists
	permissionBoundaryArn := boundaryPolicyArn(acc.AccountId)
	if err := upsertPermissionBoundary(ctx, iamSvc, bootstrapRole, permissionBoundaryArn); err != nil {
		return err
	}

	// create all roles
	for _, r := range acc.Roles {
		// set permission boundary
		r.PermissionBoundary = permissionBoundaryArn

		if err := SyncRole(ctx, iamSvc, &r); err != nil {
			return err
		}
	}

	return nil
}
func shortRoleName(roleName string) string {
	roleName = fmt.Sprintf("%s-%s", uniqSuffix, roleName)
	if len(roleName) > 64 {
		hash := md5.Sum([]byte(roleName))
		roleName = roleName[:64-len(hash)] + string(hash[:])
	}
	return roleName
}

func boundaryPolicyArn(accountId string) string {
	return arn.ARN{
		Service:   "iam",
		Resource:  fmt.Sprintf("policy/%s", permissionBoundaryName),
		AccountID: accountId,
	}.String()
}

func roleArn(accountId string, roleName string) string {
	return arn.ARN{
		Service:   "iam",
		Resource:  fmt.Sprintf("role/%s", roleName),
		AccountID: accountId,
	}.String()
}

func bootstrapRoleArn(accountId string) string {
	return roleArn(accountId, bootstrapRoleName)
}

func durationToAwsTime(d time.Duration) *int32 {
	v := int32(d.Seconds())
	return &v
}

func mapToAwsTags(tagMap map[string]string) []iamTypes.Tag {
	tags := []iamTypes.Tag{}
	// add defaults
	for k, v := range defaultTags {
		tags = append(tags, iamTypes.Tag{Key: &k, Value: &v})
	}

	for k, v := range tagMap {
		tags = append(tags, iamTypes.Tag{Key: &k, Value: &v})
	}
	return tags
}
