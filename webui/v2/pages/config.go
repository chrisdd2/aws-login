package pages

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"slices"
	"time"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/store"
	"github.com/chrisdd2/aws-login/webui/v2/middleware"
	"github.com/chrisdd2/aws-login/webui/v2/types"
	"github.com/go-chi/chi/v5"
	"sigs.k8s.io/yaml"
)

const configTemplate = `
{{define "config-page"}}
<div class="card">
    <div class="page-header flex justify-between items-center">
        <div>
            <h1 class="page-title">Configuration</h1>
            <p class="page-subtitle">Manage roles, accounts, users, and policies</p>
        </div>
        <div class="flex gap-sm">
            <a href="{{.BasePath}}/config/export" class="btn btn-outline btn-sm" target="_blank">
                Export
            </a>
            <form action="{{.BasePath}}/config/import" method="post" enctype="multipart/form-data"
                  style="display: inline;">
                <label class="btn btn-outline btn-sm" style="cursor: pointer;">
                    Import
                    <input type="file" name="file" accept=".yaml,.yml" style="display: none;"
                           onchange="this.form.submit()">
                </label>
            </form>
            <a href="{{.BasePath}}/config/sync" class="btn btn-primary btn-sm" target="_blank">
                Sync
            </a>
        </div>
    </div>

    <!-- Tabs -->
    <div class="config-tabs">
        <button class="tab-btn active" data-tab="roles">Roles</button>
        <button class="tab-btn" data-tab="accounts">Accounts</button>
        <button class="tab-btn" data-tab="users">Users</button>
        <button class="tab-btn" data-tab="policies">Policies</button>
    </div>

    <!-- Roles Tab -->
    <div class="tab-content active" id="tab-roles">
        {{if not .Roles}}
        <p class="text-muted text-center mt-lg">No roles configured.</p>
        {{else}}
        <div class="table-container">
            <table class="table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Permissions</th>
                        <th>Account</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Roles}}
                    <tr>
                        <td>{{.RoleName}}</td>
                        <td>
                            {{range .Permissions}}
                            <span class="badge badge-primary">{{.}}</span>
                            {{end}}
                        </td>
                        <td>{{.AccountName}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}
    </div>

    <!-- Accounts Tab -->
    <div class="tab-content" id="tab-accounts">
        {{if not .Accounts}}
        <p class="text-muted text-center mt-lg">No accounts configured.</p>
        {{else}}
        <div class="table-container">
            <table class="table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>AWS Account ID</th>
                        <th>Role ARN</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Accounts}}
                    <tr>
                        <td>{{.AccountName}}</td>
                        <td>{{.AwsAccountId}}</td>
                        <td class="text-sm text-muted">{{.RoleArn}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}
    </div>

    <!-- Users Tab -->
    <div class="tab-content" id="tab-users">
        {{if not .Users}}
        <p class="text-muted text-center mt-lg">No users configured.</p>
        {{else}}
        <div class="table-container">
            <table class="table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Roles</th>
                        <th>Type</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Users}}
                    <tr>
                        <td>{{.Username}}</td>
                        <td>
                            {{range .Roles}}
                            <span class="badge badge-primary">{{.}}</span>
                            {{end}}
                        </td>
                        <td>{{.Type}}</td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}
    </div>

    <!-- Policies Tab -->
    <div class="tab-content" id="tab-policies">
        {{if not .Policies}}
        <p class="text-muted text-center mt-lg">No policies configured.</p>
        {{else}}
        <div class="table-container">
            <table class="table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Document</th>
                    </tr>
                </thead>
                <tbody>
                    {{range .Policies}}
                    <tr>
                        <td>{{.PolicyName}}</td>
                        <td>
                            <details>
                                <summary class="text-sm text-primary" style="cursor: pointer;">View Policy</summary>
                                <pre class="mt-md p-md" style="background: var(--color-bg); border-radius: var(--radius-md); overflow-x: auto;">{{.PolicyDocument}}</pre>
                            </details>
                        </td>
                    </tr>
                    {{end}}
                </tbody>
            </table>
        </div>
        {{end}}
    </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function() {
    const tabBtns = document.querySelectorAll('.tab-btn');
    const tabContents = document.querySelectorAll('.tab-content');

    tabBtns.forEach(function(btn) {
        btn.addEventListener('click', function() {
            const tabId = this.dataset.tab;

            tabBtns.forEach(function(b) { b.classList.remove('active'); });
            tabContents.forEach(function(c) { c.classList.remove('active'); });

            this.classList.add('active');
            document.getElementById('tab-' + tabId).classList.add('active');
        });
    });
});
</script>

<style>
.config-tabs {
    display: flex;
    gap: var(--spacing-sm);
    margin-bottom: var(--spacing-lg);
    border-bottom: 1px solid var(--color-border);
    padding-bottom: var(--spacing-sm);
}

.tab-btn {
    padding: var(--spacing-sm) var(--spacing-lg);
    border: none;
    background: transparent;
    color: var(--color-text-muted);
    cursor: pointer;
    border-radius: var(--radius-md) var(--radius-md) 0 0;
    font-weight: 500;
    transition: all var(--transition-fast);
}

.tab-btn:hover {
    color: var(--color-text);
    background: rgba(0, 0, 0, 0.05);
}

.tab-btn.active {
    color: var(--color-primary);
    border-bottom: 2px solid var(--color-primary);
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

.badge-primary {
    background: var(--color-primary);
}

.mt-lg { margin-top: var(--spacing-lg); }
.mt-md { margin-top: var(--spacing-md); }
.p-md { padding: var(--spacing-md); }
pre { margin: 0; font-size: 0.8125rem; }
</style>
{{end}}
`

type ConfigPageData struct {
	BasePath string
	Roles    []store.RoleView
	Accounts []store.AccountView
	Users    []store.UserView
	Policies []store.PolicyView
}

type ConfigPage struct {
	basePath string
	cfg      *appconfig.AppConfig
	store    store.Store
	tpl      *template.Template
	root     types.LayoutRenderer
	lastSync time.Time
}

func NewConfigPage(basePath string, cfg *appconfig.AppConfig, store store.Store, root types.LayoutRenderer) (*ConfigPage, error) {
	tpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config template: %w", err)
	}

	return &ConfigPage{
		basePath: basePath,
		cfg:      cfg,
		store:    store,
		tpl:      tpl,
		root:     root,
	}, nil
}

func (p *ConfigPage) Router() chi.Router {
	r := chi.NewMux()
	r.Get("/", p.Render)
	r.Get("/export", p.Export)
	r.Post("/import", p.Import)
	r.Get("/sync", p.Sync)
	return r
}

func (p *ConfigPage) Render(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	roles, err := store.RolesView(ctx, p.store)
	if err != nil {
		sendError(w, r, fmt.Errorf("failed to get roles: %w", err))
		return
	}

	accounts, err := store.AccountsView(ctx, p.store)
	if err != nil {
		sendError(w, r, fmt.Errorf("failed to get accounts: %w", err))
		return
	}

	users, err := store.UsersView(ctx, p.store)
	if err != nil {
		sendError(w, r, fmt.Errorf("failed to get users: %w", err))
		return
	}

	policies, err := store.PoliciesView(ctx, p.store)
	if err != nil {
		sendError(w, r, fmt.Errorf("failed to get policies: %w", err))
		return
	}

	data := ConfigPageData{
		BasePath: p.basePath,
		Roles:    roles,
		Accounts: accounts,
		Users:    users,
		Policies: policies,
	}

	var buf bytes.Buffer
	if err := p.tpl.ExecuteTemplate(&buf, "config-page", data); err != nil {
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

func (p *ConfigPage) Export(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	st, err := store.Export(ctx, p.store)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/yaml")
	buf, _ := yaml.Marshal(&st)
	w.Write([]byte(buf))
}

func (p *ConfigPage) Import(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	defer file.Close()

	fs := store.FileStore{}
	if err := fs.LoadYaml(file); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	changes, err := store.Import(ctx, p.store, &fs.MemoryStore)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	p.lastSync = time.Now()
	w.Write([]byte(fmt.Sprintf("Imported successfully. Changes: %d", len(changes))))
}

func (p *ConfigPage) Sync(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil || !user.Superuser {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	p.lastSync = time.Now()
	w.Write([]byte("Synced successfully at " + p.lastSync.Format(time.RFC3339)))
}

func stringInSlice(s string, list []string) bool {
	return slices.Contains(list, s)
}
