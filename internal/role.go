package internal

import (
	"context"
	"crypto/md5"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamTypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
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

const uniqPrefix = "fea85e636e374e9bfb9488817817674"

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
		if _, ok := errors.AsType[*iamTypes.NoSuchEntityException](err); ok {
			// role doesn't exist
			return MaybeWrap(createRole(ctx, iamSvc, opts), "createRole")
		}
		return WrapError(err, "iam.GetRole")
	}
	// check if the basic stuff of the role need update
	if opts.Description != aws.ToString(resp.Role.Description) || int32(opts.MaxSessionDuration.Seconds()) != aws.ToInt32(resp.Role.MaxSessionDuration) {
		_, err := iamSvc.UpdateRole(ctx, &iam.UpdateRoleInput{RoleName: resp.Role.RoleName, Description: &opts.Description, MaxSessionDuration: durationToAwsTime(opts.MaxSessionDuration)})
		if err != nil {
			return WrapError(err, "iam.UpdateRole")
		}
	}

	if resp.Role.PermissionsBoundary != nil {
		if _, err := iamSvc.DeleteRolePermissionsBoundary(ctx, &iam.DeleteRolePermissionsBoundaryInput{RoleName: resp.Role.RoleName}); err != nil {
			return WrapError(err, "iam.DeleteRolePermissionBoundary")
		}
	}
	if opts.PermissionBoundary != "" {
		if _, err := iamSvc.PutRolePermissionsBoundary(ctx, &iam.PutRolePermissionsBoundaryInput{PermissionsBoundary: &opts.PermissionBoundary, RoleName: resp.Role.RoleName}); err != nil {
			return WrapError(err, "iam.PutRolePermissionBoundary")
		}
	}

	if opts.AssumeRoleDocument != aws.ToString(resp.Role.AssumeRolePolicyDocument) {
		_, err := iamSvc.UpdateAssumeRolePolicy(ctx, &iam.UpdateAssumeRolePolicyInput{PolicyDocument: &opts.AssumeRoleDocument, RoleName: resp.Role.RoleName})
		if err != nil {
			return WrapError(err, "iam.UpdateAssumeRolePolicy")
		}
	}
	// update tags, no reason to check
	_, err = iamSvc.TagRole(ctx, &iam.TagRoleInput{RoleName: resp.Role.RoleName, Tags: mapToAwsTags(opts.Tags)})
	if err != nil {
		return WrapError(err, "iam.TagRole")
	}

	// managed policies
	managedPolicyPaginator := iam.NewListAttachedRolePoliciesPaginator(iamSvc, &iam.ListAttachedRolePoliciesInput{RoleName: resp.Role.RoleName})
	// to remove
	managedPolicyToIgnore := []string{}
	managedPolicyToRemove := []string{}
	for managedPolicyPaginator.HasMorePages() {
		policies, err := managedPolicyPaginator.NextPage(ctx)
		if err != nil {
			return WrapError(err, "ListAttachedRolePolicies.NextPage")
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
			return WrapError(err, "DetachRolePolicy")
		}
	}
	for _, p := range opts.ManagedPolicies {
		if slices.Contains(managedPolicyToIgnore, p) {
			continue
		}
		_, err := iamSvc.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{RoleName: resp.Role.RoleName, PolicyArn: &p})
		if err != nil {
			return WrapError(err, "AttachRolePolicy")
		}
	}

	policiesToRemove := []string{}
	// inline policies
	policiesPaginator := iam.NewListRolePoliciesPaginator(iamSvc, &iam.ListRolePoliciesInput{RoleName: resp.Role.RoleName})
	for policiesPaginator.HasMorePages() {
		policies, err := policiesPaginator.NextPage(ctx)
		if err != nil {
			return WrapError(err, "ListRolePolicies.NextPage")
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
			return WrapError(err, "DeleteRolePolicy")
		}
	}
	for name, document := range opts.InlinePolicies {
		_, err := iamSvc.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			PolicyDocument: &document,
			PolicyName:     &name,
			RoleName:       &opts.RoleName,
		})
		if err != nil {
			return WrapError(err, "PutRolePolicy")
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
		return WrapError(err, "iam.CreateRole")
	}
	for _, p := range opts.ManagedPolicies {
		_, err := iamSvc.AttachRolePolicy(ctx, &iam.AttachRolePolicyInput{PolicyArn: &p, RoleName: &opts.RoleName})
		if err != nil {
			return WrapError(err, "iam.AttachRolePolicy")
		}
	}
	for name, document := range opts.InlinePolicies {
		_, err := iamSvc.PutRolePolicy(ctx, &iam.PutRolePolicyInput{
			PolicyDocument: &document,
			PolicyName:     &name,
			RoleName:       &opts.RoleName,
		})
		if err != nil {
			return WrapError(err, "iam.PutRolePolicy")
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
			"iam": marshalPolicy(policyStatement{
				Effect:   "Allow",
				Action:   []string{"iam:*"},
				Resource: []string{"*"},
			}),
		},
		AssumeRoleDocument: trustPolicy(principalArn),
	})
}

type resolvedAccount struct {
	Name      string
	AccountId string
	Roles     []RoleOptions
}

func SyncRoles(ctx context.Context, stsSvc *sts.Client, roles []Role) error {
	whoami, err := stsSvc.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return WrapError(err, "sts.GetCallerIdentity")
	}

	accounts := map[string][]Role{}
	for _, r := range roles {
		accounts[r.AccountId] = append(accounts[r.AccountId], r)
	}

	bootstrapTrustPolicy := trustPolicy(*whoami.Arn)

	eg := errgroup.Group{}

	for acc, roles := range accounts {
		eg.Go(func() error {
			return SyncAccount(ctx, stsSvc, acc, roles, bootstrapTrustPolicy)
		})
	}
	return MaybeWrap(eg.Wait(), "SyncAccount.Groups")
}

func upsertPermissionBoundary(ctx context.Context, iamSvc *iam.Client, bootstrapRoleArn, permissionBoundaryArn string) error {
	expectedPolicyDocument := minimizePolicy(boundaryPolicy(permissionBoundaryArn, bootstrapRoleArn))

	policyResp, err := iamSvc.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: &permissionBoundaryArn})
	if err != nil {
		if _, ok := errors.AsType[*iamTypes.NoSuchEntityException](err); ok {
			// role doesn't exist
			_, err := iamSvc.CreatePolicy(ctx, &iam.CreatePolicyInput{
				PolicyDocument: &expectedPolicyDocument,
				PolicyName:     &permissionBoundaryName,
				Description:    aws.String("aws-login iam boundary"),
				Tags:           mapToAwsTags(nil),
			})
			if err != nil {
				return WrapError(err, "iam.CreatePolicy")
			}
			return nil
		}
		if _, ok := errors.AsType[*iamTypes.EntityAlreadyExistsException](err); !ok {
			return WrapError(err, "iam.GetPolicy")
		}
	}
	// make sure the document is the same

	resp, err := iamSvc.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: policyResp.Policy.Arn, VersionId: policyResp.Policy.DefaultVersionId})
	if err != nil {
		return WrapError(err, "iam.GetPolicyVersion")
	}
	unescaped, _ := url.QueryUnescape(aws.ToString(resp.PolicyVersion.Document))
	currentPolicy := minimizePolicy(unescaped)
	if currentPolicy != expectedPolicyDocument {
		// delete the earlier one
		versionResp, err := iamSvc.ListPolicyVersions(ctx, &iam.ListPolicyVersionsInput{PolicyArn: policyResp.Policy.Arn})
		if err != nil {
			return WrapError(err, "ListPolicyVersions")
		}
		if len(versionResp.Versions) > 1 {
			for _, v := range versionResp.Versions {
				if aws.ToString(v.VersionId) == aws.ToString(resp.PolicyVersion.VersionId) {
					continue
				}
				if _, err := iamSvc.DeletePolicyVersion(ctx, &iam.DeletePolicyVersionInput{PolicyArn: policyResp.Policy.Arn, VersionId: v.VersionId}); err != nil {
					return WrapError(err, "DeletePolicyVersion")
				}
				break
			}
		}
		// put ours
		if _, err := iamSvc.CreatePolicyVersion(ctx, &iam.CreatePolicyVersionInput{PolicyArn: policyResp.Policy.Arn, PolicyDocument: &expectedPolicyDocument, SetAsDefault: true}); err != nil {
			return WrapError(err, "CreatePolicyVersion")
		}
	}
	return nil
}

func SyncAccount(ctx context.Context, stsSvc *sts.Client, accountId string, roles []Role, assumeRoleDocument string) error {
	bootstrapRole := BootstrapRoleArn(accountId)
	cfg, err := config.LoadDefaultConfig(
		ctx,
		config.WithCredentialsProvider(
			stscreds.NewAssumeRoleProvider(stsSvc, bootstrapRole),
		),
	)
	if err != nil {
		return WrapError(err, "aws.LoadDefaultConfig")
	}
	iamSvc := iam.NewFromConfig(cfg)
	// make sure permission boundary exists
	permissionBoundaryArn := boundaryPolicyArn(accountId)
	if err := upsertPermissionBoundary(ctx, iamSvc, bootstrapRole, permissionBoundaryArn); err != nil {
		return WrapError(err, "unsertPermissionBoundary")
	}

	// create all roles
	for _, r := range roles {
		opts := RoleOptions{
			RoleName:           r.Name,
			MaxSessionDuration: r.MaxSessionDuration,
			InlinePolicies:     r.Policies,
			ManagedPolicies:    r.ManagedPolicies,
			Tags:               r.Tags,
			AssumeRoleDocument: assumeRoleDocument,
			PermissionBoundary: permissionBoundaryArn,
		}
		if opts.MaxSessionDuration == 0 {
			opts.MaxSessionDuration = time.Hour * 8
		}
		if r.NoIamBoundary {
			opts.PermissionBoundary = ""
		}

		if err := SyncRole(ctx, iamSvc, &opts); err != nil {
			return WrapError(err, "SyncRole")
		}
	}
	return nil
}
func shortRoleName(roleName string) string {
	roleName = fmt.Sprintf("%s-%s", uniqPrefix, roleName)
	if len(roleName) > 64 {
		hash := fmt.Sprintf("%x", md5.Sum([]byte(roleName)))
		roleName = roleName[:64-len(hash)] + hash
	}
	return roleName
}

func boundaryPolicyArn(accountId string) string {
	return fmt.Sprintf("arn:aws:iam::%s:policy/%s", accountId, permissionBoundaryName)
}

func RoleArn(accountId string, roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountId, roleName)
}

func BootstrapRoleArn(accountId string) string {
	return RoleArn(accountId, bootstrapRoleName)
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
