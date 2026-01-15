package account

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"reflect"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/aws"
	"github.com/chrisdd2/aws-login/internal/services/storage"
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

type AccountService interface {
	Deploy(ctx context.Context, userId string, accountId string) error
	DeploymentStatus(ctx context.Context, accountId string) (DeploymentStatus, error)
	StackUpdates(ctx context.Context, accountName string, stackId string) ([]aws.StackEvent, error)
	DestroyStack(ctx context.Context, accountName string, username string) (string, error)
	GetFromAccountName(ctx context.Context, name string) (*appconfig.Account, error)
	ListAccounts(ctx context.Context) ([]*appconfig.Account, error)
	BootstrapTemplate(ctx context.Context, accountName string) (string, error)
}

type accountService struct {
	storage storage.Storage
	aws     aws.AwsApiCaller
	ev      storage.Eventer
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
	// Permission check
	user, err := a.storage.GetUser(ctx, userId)
	if err != nil {
		return err
	}
	if !(user.Superuser) {
		return ErrNoPermission
	}

	templateString, err := generateStackTemplate(ctx, a.storage, accountId)
	if err != nil {
		return fmt.Errorf("generateStackTemplate: %w", err)
	}

	// Deploy the stack
	acc, err := a.storage.GetAccount(ctx, accountId)
	if err != nil {
		return err
	}
	a.ev.Publish(ctx, "account_deploy", map[string]string{"username": userId, "account_name": accountId})
	return a.aws.DeployStack(ctx, acc.Name, acc.AwsAccountId, aws.StackName.Value(accountId), templateString, nil)
}
func (a *accountService) GetFromAccountName(ctx context.Context, name string) (*appconfig.Account, error) {
	return a.storage.GetAccount(ctx, name)
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

func NewAccountService(store storage.Storage, aws aws.AwsApiCaller, ev storage.Eventer) AccountService {
	return &accountService{
		storage: store,
		aws:     aws,
		ev:      ev,
	}
}

func (a *accountService) ListAccounts(ctx context.Context) ([]*appconfig.Account, error) {
	return a.storage.ListAccounts(ctx)
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
	acc, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return status, fmt.Errorf("storage.GetAccount: %w", err)
	}
	templateString, err := generateStackTemplate(ctx, a.storage, acc.Name)
	if err != nil {
		return status, fmt.Errorf("generateStackTemplate: %w", err)
	}
	currentTemplateString, err := a.aws.StackTemplate(ctx, accountName, acc.AwsAccountId, aws.StackName.Value(accountName))
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
	acc, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return nil, fmt.Errorf("accountService.StackUpdates: storage.GetAccount: %w", err)
	}
	if stackId == "" {
		stackId = aws.StackName.Value(accountName)
	}
	events, err := a.aws.TopStackEvents(ctx, accountName, acc.AwsAccountId, stackId)
	if err != nil {
		return nil, fmt.Errorf("accountService.StackUpdates: aws.WatchStackEvents: %w", err)
	}
	return events, nil
}

func generateStackTemplate(ctx context.Context, store storage.Storage, account string) (string, error) {
	// gather up all the roles that need to be deployed as part of the stack
	type CfnRole struct {
		LogicalName        string
		RoleName           string
		ManagedPolicies    []string
		Policies           map[string]string
		MaxSessionDuration time.Duration
	}

	roles, err := store.ListRolesForAccount(ctx, account)
	cfnroles := []CfnRole{}
	for _, item := range roles {
		resolvedPolicies := map[string]string{}
		for name, id := range item.Policies {
			policy, err := store.GetInlinePolicy(ctx, id)
			if err != nil {
				return "", fmt.Errorf("storage.GetInlinePolicy: %w", err)
			}
			resolvedPolicies[name] = policy.Document
		}

		cfnroles = append(cfnroles, CfnRole{
			LogicalName:        roleLogicalName(item.Name),
			RoleName:           item.Name,
			ManagedPolicies:    item.ManagedPolicies,
			Policies:           resolvedPolicies,
			MaxSessionDuration: item.MaxSessionDuration,
		})
	}
	log.Println(roleStackTemplate.Templates())
	templateString, err := templateExecuteToString(roleStackTemplate, struct{ Roles []CfnRole }{Roles: cfnroles})
	if err != nil {
		return "", err
	}
	return templateString, nil
}

func (a *accountService) DestroyStack(ctx context.Context, accountName string, username string) (string, error) {
	acc, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return "", fmt.Errorf("accountService.DestroyStack: storage.GetAccount: %w", err)
	}
	a.ev.Publish(ctx, "account_destroy", map[string]string{"username": username, "account_name": accountName})
	stackId, err := a.aws.DestroyStack(ctx, accountName, acc.AwsAccountId, aws.StackName.Value(accountName))
	if err != nil {
		return "", fmt.Errorf("accountService.DestroyStack: aws.DestroyStack: %w", err)
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
	_, err := a.storage.GetAccount(ctx, accountName)
	if err != nil {
		return "", fmt.Errorf("accountService.BootstrapTemplate: storage.GetAccount: %w", err)
	}
	_, arn, err := a.aws.WhoAmI(ctx)
	if err != nil {
		return "", fmt.Errorf("accountService.BootstrapTemplate: aws.WhoAmi: %w", err)
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
