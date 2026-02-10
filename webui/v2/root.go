package v2

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/webui/v2/types"
	"github.com/go-chi/chi/v5"
)

const rootTemplate = `
{{define "topheader"}}
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.AppName}}</title>
    <link rel="stylesheet" href="/v2/static/reset.css">
    <link rel="stylesheet" href="/v2/static/main.css">
    <script src="/v2/static/htmx.min.js"></script>
</head>
{{end}}

{{define "header"}}
{{template "topheader" .}}
<body class="app-container">
    <header class="header">
        <div class="header-inner">
            <a href="/" class="logo" hx-get="/" hx-target="#main-content" hx-push-url="/">
                <span class="icon">&#9729;</span>
                <span>{{.AppName}}</span>
            </a>
            <nav class="nav">
                {{if .IsAuthenticated}}
                <a href="/roles"
                   class="nav-link{{if eq .CurrentPath "/roles"}} active{{end}}"
                   hx-get="/roles"
                   hx-target="#main-content"
                   hx-push-url="/roles">
                    Roles
                </a>
                {{if .HasAdmin}}
                <a href="/accounts"
                   class="nav-link{{if eq .CurrentPath "/accounts"}} active{{end}}"
                   hx-get="/accounts"
                   hx-target="#main-content"
                   hx-push-url="/accounts">
                    Accounts
                </a>
                <a href="/config"
                   class="nav-link{{if eq .CurrentPath "/config"}} active{{end}}"
                   hx-get="/config"
                   hx-target="#main-content"
                   hx-push-url="/config">
                    Configuration
                </a>
                {{end}}
                {{end}}
            </nav>
            <div class="header-actions">
                {{if .IsAuthenticated}}
                <div class="user-info">
                    <div class="user-avatar">{{.Initials}}</div>
                    <span class="user-name">{{.Username}}</span>
                    <span class="status-indicator" title="Logged in"></span>
                </div>
                <a href="/logout" class="btn btn-outline btn-sm" title="Logout">
                    <span class="icon">&#10140;</span>
                </a>
                {{else}}
                <a href="/login" class="btn btn-primary btn-sm" hx-get="/login" hx-target="#main-content" hx-push-url="/login">
                    Sign In
                </a>
                {{end}}
            </div>
        </div>
    </header>
{{end}}

{{define "footer"}}
    <footer class="footer">
        <p class="footer-text">{{.AppName}} - Secure access to your AWS accounts</p>
    </footer>
</body>
</html>
{{end}}

{{define "root-layout"}}
{{template "header" .}}
    <main id="main-content" class="main-content">
        <div class="page-wrapper">
            {{.Content}}
        </div>
    </main>
{{template "footer" .}}
{{end}}
`

type RootPage struct {
	basePath string
	cfg      *appconfig.AppConfig
	tpl      *template.Template
}

func NewRootPage(basePath string, cfg *appconfig.AppConfig) (*RootPage, error) {
	tpl, err := template.New("root").Funcs(template.FuncMap{
		"url": absolutePath(basePath),
	}).Parse(rootTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse root template: %w", err)
	}

	return &RootPage{
		basePath: basePath,
		cfg:      cfg,
		tpl:      tpl,
	}, nil
}

func absolutePath(basePath string) func(string) string {
	return func(path string) string {
		u, err := url.JoinPath(basePath, path)
		if err != nil {
			return path
		}
		return u
	}
}

func (p *RootPage) RenderRoot(w http.ResponseWriter, r *http.Request, content template.HTML, data types.LayoutData) {
	data.AppName = p.cfg.Name
	data.IsHtmxRequest = isHtmxRequest(r)
	data.CurrentPath = r.URL.Path

	if data.Content != "" {
		// Content already set
	} else {
		data.Content = content
	}

	if err := p.tpl.ExecuteTemplate(w, "root-layout", data); err != nil {
		http.Error(w, fmt.Sprintf("failed to render root layout: %v", err), http.StatusInternalServerError)
	}
}

func (p *RootPage) RenderHeader(w http.ResponseWriter, r *http.Request, data types.LayoutData) {
	data.AppName = p.cfg.Name
	data.IsHtmxRequest = isHtmxRequest(r)
	data.CurrentPath = r.URL.Path

	if err := p.tpl.ExecuteTemplate(w, "header", data); err != nil {
		http.Error(w, fmt.Sprintf("failed to render header: %v", err), http.StatusInternalServerError)
	}
}

func (p *RootPage) RenderFooter(w http.ResponseWriter, r *http.Request) {
	data := types.LayoutData{
		AppName: p.cfg.Name,
	}
	if err := p.tpl.ExecuteTemplate(w, "footer", data); err != nil {
		http.Error(w, fmt.Sprintf("failed to render footer: %v", err), http.StatusInternalServerError)
	}
}

func (p *RootPage) Router() chi.Router {
	return chi.NewMux()
}

func isHtmxRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}
