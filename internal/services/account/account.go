package account

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/chrisdd2/aws-login/internal/aws"
	"github.com/chrisdd2/aws-login/store"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"sigs.k8s.io/yaml"
)

var ErrNoPermission = errors.New("no permission for this action (only superusers)")

type DeploymentStatus struct {
	StackExists    bool
	NeedsUpdate    bool
	NeedsBootstrap bool
}

type AccountInfo struct {
	Name         string
	AwsAccountId string
}

type AccountService interface {
	Deploy(ctx context.Context, userId string, accountId string) error
	DeploymentStatus(ctx context.Context, accountId string) (DeploymentStatus, error)
	StackUpdates(ctx context.Context, accountName string, stackId string) ([]aws.StackEvent, error)
	DestroyStack(ctx context.Context, accountName string, username string) (string, error)
	ListAccounts(ctx context.Context) ([]AccountInfo, error)
	BootstrapTemplate(ctx context.Context, accountName string) (string, error)
}

type accountService struct {
	storage store.Store
	aws     aws.AwsApiCaller
}

func templateExecuteToString[T any](tmpl *template.Template, data T) (string, error) {
	buf := bytes.Buffer{}
	err := tmpl.Execute(&buf, data)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

func (a *accountService) Deploy(ctx context.Context, userId string, accountId string) error {
	templateString, err := generateStackTemplate(ctx, a.storage, accountId)
	if err != nil {
		return fmt.Errorf("generateStackTemplate: %w", err)
	}

	// Deploy the stack
	acc, err := store.GetResource(ctx, a.storage, store.ResourceTypeAccount, accountId)
	if err != nil {
		return fmt.Errorf("storage.GetAccount: %w", err)
	}
	return a.aws.DeployStack(ctx, acc.Id, acc.Metadata["aws_account_id"], aws.StackName.Value(accountId), templateString, nil)
}

func roleLogicalName(roleName string) string {
	// remove invalid characters
	normalized := strings.ReplaceAll(strings.ReplaceAll(roleName, "-", " "), "/", " ")
	// capitalize
	normalized = cases.Title(language.English, cases.Compact).String(strings.ToLower(normalized))
	// remove spaces
	return strings.Join(strings.Split(normalized, " "), "")
}
func maxSessionDuration(duration time.Duration) string {
	return strconv.Itoa(int((duration) / time.Second))
}

func NewAccountService(store store.Store, aws aws.AwsApiCaller) AccountService {
	return &accountService{
		storage: store,
		aws:     aws,
	}
}

func (a *accountService) ListAccounts(ctx context.Context) ([]AccountInfo, error) {
	accounts, err := a.storage.GetResources(ctx, store.ResourceTypeAccount)
	if err != nil {
		return nil, err
	}
	ret := []AccountInfo{}
	for _, acc := range accounts {
		ret = append(ret, AccountInfo{
			Name:         acc.Id,
			AwsAccountId: acc.Metadata["aws_account_id"],
		})
	}
	return ret, nil
}

func equalYaml(a string, b string) (bool, error) {
	am := map[string]any{}
	bm := map[string]any{}
	if err := yaml.Unmarshal([]byte(a), &am, yaml.DisallowUnknownFields); err != nil {
		return false, err
	}
	if err := yaml.Unmarshal([]byte(b), &bm, yaml.DisallowUnknownFields); err != nil {
		return false, err
	}
	return reflect.DeepEqual(am, bm), nil
}

func (a *accountService) DeploymentStatus(ctx context.Context, accountName string) (DeploymentStatus, error) {
	status := DeploymentStatus{
		StackExists:    true,
		NeedsUpdate:    false,
		NeedsBootstrap: false,
	}
	acc, err := store.GetResource(ctx, a.storage, store.ResourceTypeAccount, accountName)
	if err != nil {
		return status, fmt.Errorf("storage.GetAccount: %w", err)
	}
	templateString, err := generateStackTemplate(ctx, a.storage, acc.Id)
	if err != nil {
		return status, fmt.Errorf("generateStackTemplate: %w", err)
	}
	currentTemplateString, err := a.aws.StackTemplate(ctx, accountName, acc.Metadata["aws_account_id"], aws.StackName.Value(accountName))
	if errors.Is(err, aws.ErrStackNotExist) {
		status.StackExists = false
		return status, nil
	}
	if errors.Is(err, aws.ErrNotAuthorized) {
		status.StackExists = false
		status.NeedsBootstrap = true
		return status, nil
	}
	if err != nil {
		return status, fmt.Errorf("aws.StackTemplate: %w", err)
	}
	equal, err := equalYaml(templateString, currentTemplateString)
	status.NeedsUpdate = !equal
	return status, err
}
func (a *accountService) StackUpdates(ctx context.Context, accountName string, stackId string) ([]aws.StackEvent, error) {
	acc, err := store.GetResource(ctx, a.storage, store.ResourceTypeAccount, accountName)
	if err != nil {
		return nil, fmt.Errorf("storage.GetAccount: %w", err)
	}
	if stackId == "" {
		stackId = aws.StackName.Value(accountName)
	}
	events, err := a.aws.TopStackEvents(ctx, accountName, acc.Metadata["aws_account_id"], stackId)
	if err != nil {
		return nil, fmt.Errorf("aws.TopStackEvents: %w", err)
	}
	return events, nil
}

func generateStackTemplate(ctx context.Context, st store.Store, account string) (string, error) {
	// gather up all the roles that need to be deployed as part of the stack
	type CfnRole struct {
		LogicalName        string
		RoleName           string
		ManagedPolicies    []string
		Policies           map[string]string
		MaxSessionDuration time.Duration
	}

	roles, err := st.GetResourceAttachments(ctx, store.AccountAttachmentRole, "", account)
	cfnroles := []CfnRole{}
	for _, item := range roles {
		if item.Disabled {
			continue
		}
		// clean managed policies from garbage data
		managedPolicies := store.TextArray{}
		if err := managedPolicies.Scan(item.Metadata["managed_policies"]); err != nil {
			return "", err
		}
		sessionDuration, err := time.ParseDuration(item.Metadata["max_session_duration"])
		if err != nil {
			return "", err
		}
		// gather up all the policy documents for this role
		ats, err := st.GetResourceAttachments(ctx, store.RoleAttachmentPolicy, "", item.ResourceId)
		if err != nil {
			return "", fmt.Errorf("store.ListRolePolicyAttachments: %w", err)
		}
		policies := map[string]string{}
		for _, at := range ats {
			p, err := store.GetResource(ctx, st, store.ResourceTypePolicy, at.ResourceId)
			if err != nil {
				return "", fmt.Errorf("store.GetPolicy: %w", err)
			}
			if p.Disabled {
				continue
			}
			policies[at.ResourceId] = p.Document
		}
		cfnroles = append(cfnroles, CfnRole{
			LogicalName:        roleLogicalName(item.ResourceId),
			RoleName:           item.ResourceId,
			ManagedPolicies:    []string(managedPolicies),
			MaxSessionDuration: sessionDuration,
			Policies:           policies,
		})
	}
	templateString, err := templateExecuteToString(roleStackTemplate, struct{ Roles []CfnRole }{Roles: cfnroles})
	if err != nil {
		return "", fmt.Errorf("templateExecuteToString: %w", err)
	}
	return templateString, nil
}

func (a *accountService) DestroyStack(ctx context.Context, accountName string, username string) (string, error) {
	acc, err := store.GetResource(ctx, a.storage, store.ResourceTypeAccount, accountName)
	if err != nil {
		return "", fmt.Errorf("storage.GetAccount: %w", err)
	}
	stackId, err := a.aws.DestroyStack(ctx, accountName, acc.Metadata["aws_account_id"], aws.StackName.Value(accountName))
	if err != nil {
		return "", fmt.Errorf("aws.DestroyStack: %w", err)
	}
	return stackId, nil

}

func loadTemplates(fs fs.FS, name string) *template.Template {
	funcs := template.FuncMap{
		"roleLogicalName":    roleLogicalName,
		"maxSessionDuration": maxSessionDuration,
	}
	return template.Must(template.New(
		strings.Split(name, ".")[0]).Funcs(funcs).ParseFS(fs, name),
	).Lookup(name)
}

var (
	//go:embed *.gotmpl
	files                     embed.FS
	roleStackTemplate         = loadTemplates(files, "role-stack.gotmpl")
	bootstrapStackTemplateCfn = loadTemplates(files, "bootstrap-stack.gotmpl")
)

func (a *accountService) BootstrapTemplate(ctx context.Context, accountName string) (string, error) {
	_, err := store.GetResource(ctx, a.storage, store.ResourceTypeAccount, accountName)
	if err != nil {
		return "", fmt.Errorf("storage.GetAccount: %w", err)
	}
	_, arn, err := a.aws.WhoAmI(ctx)
	if err != nil {
		return "", fmt.Errorf("aws.WhoAmI: %w", err)
	}
	tmpl := bootstrapStackTemplateCfn
	return templateExecuteToString(tmpl,
		struct {
			TargetStackName string
			Principal       string
			OpsRoleName     string
			AccountName     string
		}{
			TargetStackName: aws.StackName.Value(accountName),
			Principal:       arn,
			OpsRoleName:     aws.OpsRole.Value(accountName),
			AccountName:     accountName,
		})
}
