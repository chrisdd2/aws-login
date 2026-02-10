package pages

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"slices"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services/account"
	"github.com/chrisdd2/aws-login/webui/v2/middleware"
	"github.com/chrisdd2/aws-login/webui/v2/types"
	"github.com/go-chi/chi/v5"
)

const accountsTemplate = `
{{define "accounts-page"}}
<div class="card">
    <div class="page-header">
        <h1 class="page-title">Deploy Changes</h1>
        <p class="page-subtitle">Trigger deployments for the accounts you manage</p>
    </div>

    {{if not .Accounts}}
    <div class="alert alert-warning">
        <span class="icon">&#9888;</span>
        <span>No accounts found. Contact an administrator.</span>
    </div>
    {{else}}
    <div class="table-container">
        <table class="table">
            <thead>
                <tr>
                    <th>Account</th>
                    <th>Status</th>
                    <th class="text-right">Actions</th>
                </tr>
            </thead>
            <tbody>
                {{range .Accounts}}
                <tr>
                    <td>
                        <span>{{.AccountName}}</span>
                        <span class="text-muted text-sm">({{.AccountId}})</span>
                    </td>
                    <td>
                        <span class="badge badge-{{.StatusClass}}">{{.Status}}</span>
                    </td>
                    <td class="text-right">
                        <div class="flex gap-sm justify-end">
                            {{if .HasDeploy}}
                            <a href="{{$.BasePath}}/accounts/deploy?account={{.AccountName}}"
                               target="_blank" class="btn btn-primary btn-sm">
                                Deploy
                            </a>
                            {{else}}
                            <a href="{{$.BasePath}}/accounts/template?account={{.AccountName}}&name=bootstrap"
                               target="_blank" download class="btn btn-secondary btn-sm">
                                Bootstrap Template
                            </a>
                            {{end}}
                            {{if .HasStack}}
                            <a href="{{$.BasePath}}/accounts/watch?account={{.AccountName}}"
                               target="_blank" class="btn btn-outline btn-sm">
                                Watch
                            </a>
                            <a href="{{$.BasePath}}/accounts/destroy?account={{.AccountName}}"
                               target="_blank" class="btn btn-danger btn-sm">
                                Destroy
                            </a>
                            {{end}}
                        </div>
                    </td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    {{end}}
</div>
{{end}}
`

const watchTemplate = `
{{define "watch-page"}}
<div class="card">
    <div class="page-header flex justify-between items-center">
        <div>
            <h1 class="page-title">Stack Updates</h1>
            <p class="page-subtitle">Account: {{.AccountName}}</p>
        </div>
        <a href="{{.BasePath}}/accounts" class="btn btn-outline btn-sm">Back to Accounts</a>
    </div>

    {{if not .Events}}
    <div class="alert alert-warning">
        <span class="icon">&#9888;</span>
        <span>No stack events found.</span>
    </div>
    {{else}}
    <div class="table-container">
        <table class="table">
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Status</th>
                    <th>Type</th>
                    <th>Message</th>
                </tr>
            </thead>
            <tbody>
                {{range .Events}}
                <tr>
                    <td class="text-sm text-muted">{{.Timestamp}}</td>
                    <td>
                        <span class="badge badge-{{if .Success}}success{{else}}danger{{end}}">
                            {{.Status}}
                        </span>
                    </td>
                    <td>{{.ResourceType}}</td>
                    <td>{{.Message}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
    {{end}}
</div>
{{end}}
`

type Account struct {
	AccountName string
	AccountId   string
	Status      string
	StatusClass string
	HasStack    bool
	HasDeploy   bool
}

type AccountsPageData struct {
	BasePath string
	Accounts []Account
}

type WatchPageData struct {
	BasePath    string
	AccountName string
	Events      []StackEvent
}

type StackEvent struct {
	Timestamp    string
	Status       string
	ResourceType string
	Message      string
	Success      bool
}

type AccountsPage struct {
	basePath string
	cfg      *appconfig.AppConfig
	accounts account.AccountService
	tpl      *template.Template
	root     types.LayoutRenderer
}

func NewAccountsPage(basePath string, cfg *appconfig.AppConfig, accounts account.AccountService, root types.LayoutRenderer) (*AccountsPage, error) {
	tpl, err := template.New("accounts").Parse(accountsTemplate + watchTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse accounts template: %w", err)
	}

	return &AccountsPage{
		basePath: basePath,
		cfg:      cfg,
		accounts: accounts,
		tpl:      tpl,
		root:     root,
	}, nil
}

func (p *AccountsPage) Router() chi.Router {
	r := chi.NewMux()
	r.Get("/", p.Render)
	r.Get("/deploy", p.Deploy)
	r.Get("/destroy", p.Destroy)
	r.Get("/watch", p.Watch)
	r.Get("/template", p.Template)
	return r
}

func (p *AccountsPage) Render(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	accounts, err := p.accounts.ListAccounts(ctx)
	if err != nil {
		sendError(w, r, fmt.Errorf("failed to list accounts: %w", err))
	}

	templateAccounts := make([]Account, 0, len(accounts))
	for _, acc := range accounts {
		status, err := p.accounts.DeploymentStatus(ctx, acc.Name)
		if err != nil {
			continue // Skip accounts with status errors
		}

		statusMsg, statusClass := deploymentStatus(status)
		templateAccounts = append(templateAccounts, Account{
			AccountName: acc.Name,
			AccountId:   acc.AwsAccountId,
			Status:      statusMsg,
			StatusClass: statusClass,
			HasStack:    status.StackExists,
			HasDeploy:   !status.NeedsBootstrap,
		})
	}

	data := AccountsPageData{
		BasePath: p.basePath,
		Accounts: templateAccounts,
	}

	var buf bytes.Buffer
	if err := p.tpl.ExecuteTemplate(&buf, "accounts-page", data); err != nil {
		sendError(w, r, err)
		return
	}

	content := template.HTML(buf.String())
	layoutData := types.LayoutData{
		Username:        user.Username,
		Initials:        getInitials(user.Username),
		HasAdmin:        user.Superuser,
		IsAuthenticated: true,
	}
	p.root.RenderRoot(w, r, content, layoutData)
}

func (p *AccountsPage) Deploy(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	query := r.URL.Query()
	accountName := query.Get("account")
	if accountName == "" {
		http.Error(w, "account is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	err := p.accounts.Deploy(ctx, user.Username, accountName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to watch page
	http.Redirect(w, r, p.basePath+"/accounts/watch?account="+accountName, http.StatusTemporaryRedirect)
}

func (p *AccountsPage) Destroy(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	query := r.URL.Query()
	accountName := query.Get("account")
	if accountName == "" {
		http.Error(w, "account is required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	stackId, err := p.accounts.DestroyStack(ctx, accountName, user.Username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to watch page
	watchURL := p.basePath + "/accounts/watch?account=" + accountName
	if stackId != "" {
		watchURL += "&stackId=" + stackId
	}
	http.Redirect(w, r, watchURL, http.StatusTemporaryRedirect)
}

func (p *AccountsPage) Watch(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	query := r.URL.Query()
	accountName := query.Get("account")
	if accountName == "" {
		http.Error(w, "account is required", http.StatusBadRequest)
		return
	}

	stackId := query.Get("stackId")
	ctx := r.Context()
	events, err := p.accounts.StackUpdates(ctx, accountName, stackId)
	if err != nil {
		sendError(w, r, fmt.Errorf("failed to get stack updates: %w", err))
	}

	templateEvents := make([]StackEvent, 0, len(events))
	for _, e := range events {
		templateEvents = append(templateEvents, StackEvent{
			Timestamp:    e.EventTime.Format("2006-01-02 15:04:05"),
			Status:       e.ResourceStatus,
			ResourceType: e.ResourceType,
			Message:      e.ResourceStatusReason,
			Success:      slices.Contains([]string{"CREATE_COMPLETE", "UPDATE_COMPLETE"}, e.ResourceStatus),
		})
	}

	data := WatchPageData{
		BasePath:    p.basePath,
		AccountName: accountName,
		Events:      templateEvents,
	}

	if err := p.tpl.ExecuteTemplate(w, "watch-page", data); err != nil {
		sendError(w, r, err)
	}
}

func (p *AccountsPage) Template(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	query := r.URL.Query()
	accountName := query.Get("account")
	templateName := query.Get("name")

	if accountName == "" || templateName == "" {
		http.Error(w, "account and template name are required", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	var templateString string
	var err error

	switch templateName {
	case "bootstrap":
		templateString, err = p.accounts.BootstrapTemplate(ctx, accountName)
	case "roles":
		templateString, err = p.accounts.RoleStackTemplate(ctx, accountName)
	default:
		http.Error(w, "unknown template", http.StatusBadRequest)
		return
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(templateString))
}

func deploymentStatus(status account.DeploymentStatus) (string, string) {
	if status.NeedsBootstrap {
		return "Needs bootstrap", "warning"
	}
	if status.StackExists {
		if status.NeedsUpdate {
			return "Needs sync", "warning"
		}
		return "Up to date", "success"
	}
	return "Needs first deployment", "warning"
}
