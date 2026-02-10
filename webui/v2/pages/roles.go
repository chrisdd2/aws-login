package pages

import (
	"bytes"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services"
	"github.com/chrisdd2/aws-login/store"
	"github.com/chrisdd2/aws-login/webui/v2/middleware"
	"github.com/chrisdd2/aws-login/webui/v2/types"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

const rolesTemplate = `
{{define "roles-page"}}
<div class="card">
    <div class="page-header">
        <h1 class="page-title">Available Roles</h1>
        <p class="page-subtitle">Select a role to access AWS resources</p>
    </div>

    {{if not .Roles}}
    <div class="alert alert-warning">
        <span class="icon">&#9888;</span>
        <span>No roles available for your account. Contact an administrator.</span>
    </div>
    {{else}}
    <div class="table-container">
        <table class="table">
            <thead>
                <tr>
                    <th>Account</th>
                    <th>Role</th>
                    <th class="text-right">Actions</th>
                </tr>
            </thead>
            <tbody>
                {{range .Roles}}
                <tr>
                    <td>
                        <span>{{.AccountName}}</span>
                        <span class="text-muted text-sm">({{.AccountId}})</span>
                    </td>
                    <td>{{.RoleName}}</td>
                    <td class="text-right">
                        <div class="flex gap-sm justify-end">
                            {{if .HasConsole}}
                            <a href="{{$.BasePath}}/roles/console?account={{.AccountName}}&role={{.RoleName}}"
                               target="_blank" class="btn btn-primary btn-sm">
                                Console
                            </a>
                            {{end}}
                            {{if .HasCredentials}}
                            <a href="{{$.BasePath}}/roles/credentials?account={{.AccountName}}&role={{.RoleName}}"
                               target="_blank" class="btn btn-secondary btn-sm">
                                Credentials
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

type Role struct {
	AccountId      string
	AccountName    string
	RoleName       string
	HasCredentials bool
	HasConsole     bool
}

type RolesPageData struct {
	BasePath string
	Roles    []Role
}

type RolesPage struct {
	basePath string
	cfg      *appconfig.AppConfig
	roles    services.RolesService
	store    store.Store
	tpl      *template.Template
	root     types.LayoutRenderer
}

func NewRolesPage(basePath string, cfg *appconfig.AppConfig, roles services.RolesService, store store.Store, root types.LayoutRenderer) (*RolesPage, error) {
	tpl, err := template.New("roles").Parse(rolesTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse roles template: %w", err)
	}

	return &RolesPage{
		basePath: basePath,
		cfg:      cfg,
		roles:    roles,
		store:    store,
		tpl:      tpl,
		root:     root,
	}, nil
}

func (p *RolesPage) Router() chi.Router {
	r := chi.NewMux()
	r.Get("/", p.Render)
	r.Get("/console", p.Console)
	r.Get("/credentials", p.Credentials)
	return r
}

func (p *RolesPage) Render(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil {
		http.Redirect(w, r, "/v2/login", http.StatusTemporaryRedirect)
		return
	}

	ctx := r.Context()
	isAdmin := p.cfg.Auth.AdminUsername == user.Username

	roles, err := p.roles.ListRoles(ctx, user.Username, isAdmin)
	if err != nil {
		sendError(w, r, fmt.Errorf("failed to list roles: %w", err))
	}

	templateRoles := []Role{}
	for role := range roles {
		accId, err := role.AccountId(ctx, p.store)
		if err != nil {
			sendError(w, r, fmt.Errorf("failed to get account ID: %w", err))
		}

		templateRoles = append(templateRoles, Role{
			AccountId:      accId,
			AccountName:    role.AccountName,
			RoleName:       role.RoleName,
			HasCredentials: contains(role.Permissions, store.RolePermissionCredentials),
			HasConsole:     contains(role.Permissions, store.RolePermissionConsole),
		})
	}

	data := RolesPageData{
		BasePath: p.basePath,
		Roles:    templateRoles,
	}

	var buf bytes.Buffer
	if err := p.tpl.ExecuteTemplate(&buf, "roles-page", data); err != nil {
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

func (p *RolesPage) Console(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	query := r.URL.Query()
	account := query.Get("account")
	roleName := query.Get("role")

	if account == "" || roleName == "" {
		http.Error(w, "account and role are required", http.StatusBadRequest)
		return
	}

	url, err := p.roles.Console(ctx, account, roleName, user.Username)
	if err != nil {
		if err == services.ErrRoleUnauthorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sendError(w, r, fmt.Errorf("failed to get console URL: %w", err))
		return
	}
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func (p *RolesPage) Credentials(w http.ResponseWriter, r *http.Request) {
	user := middleware.GetUser(r)
	if user == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	ctx := r.Context()
	query := r.URL.Query()
	account := query.Get("account")
	roleName := query.Get("role")
	format := query.Get("format")

	if account == "" || roleName == "" {
		sendError(w, r, errors.New("account and role are required"))
		return
	}

	creds, err := p.roles.Credentials(ctx, account, roleName, user.Username)
	if err != nil {
		if err == services.ErrRoleUnauthorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sendError(w, r, fmt.Errorf("failed to get credentials: %w", err))
		return
	}

	if format == "" {
		format = "linux"
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte(creds.Format(format)))
}

func contains[T comparable](slice []T, item T) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func sendError(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	slog.Debug("http", "error", err)
	render.JSON(w, r, struct {
		Error string `json:"error"`
	}{err.Error()})
}
