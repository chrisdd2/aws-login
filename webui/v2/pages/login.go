package pages

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/chrisdd2/aws-login/appconfig"
	"github.com/chrisdd2/aws-login/internal/services"
	"github.com/chrisdd2/aws-login/webui/v2/middleware"
	"github.com/chrisdd2/aws-login/webui/v2/types"
)

const loginTemplate = `
{{define "login-page"}}
<div class="login-container">
    <div class="login-card">
        <div class="page-header text-center">
            <h1 class="login-title">{{.AppName}}</h1>
            <p class="login-subtitle">Sign in to your account</p>
        </div>

        {{if .ErrorString}}
        <div class="alert alert-error">
            <span class="icon">&#9888;</span>
            <span>{{.ErrorString}}</span>
        </div>
        {{end}}

        {{if .HasAdminPrompt}}
        <form action="{{.BasePath}}/login?type=userpass" method="post">
            <div class="form-group">
                <label class="form-label" for="username">Username</label>
                <input type="text" id="username" name="username" class="form-input"
                       placeholder="Enter your username" required>
            </div>
            <div class="form-group">
                <label class="form-label" for="password">Password</label>
                <input type="password" id="password" name="password" class="form-input"
                       placeholder="Enter your password" required>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Sign In</button>
        </form>

        {{if .HasIdp}}
        <div class="divider">
            <span class="divider-text">or</span>
        </div>
        {{end}}
        {{end}}

        {{if .HasIdp}}
        {{range .LoginTypes}}
        <a href="{{$.BasePath}}/login?type={{.Name}}" class="btn btn-secondary btn-block">
            {{.Description}}
        </a>
        {{end}}
        {{end}}
    </div>
</div>
{{end}}
`

type LoginPageData struct {
	AppName        string
	BasePath       string
	ErrorString    string
	HasAdminPrompt bool
	HasIdp         bool
	LoginTypes     []struct {
		Name        string
		Description string
	}
}

type LoginPage struct {
	basePath string
	cfg      *appconfig.AppConfig
	auths    []services.AuthService
	tpl      *template.Template
	root     types.LayoutRenderer
}

func NewLoginPage(basePath string, cfg *appconfig.AppConfig, auths []services.AuthService, root types.LayoutRenderer) (*LoginPage, error) {
	tpl, err := template.New("login").Parse(loginTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to parse login template: %w", err)
	}

	return &LoginPage{
		basePath: basePath,
		cfg:      cfg,
		auths:    auths,
		tpl:      tpl,
		root:     root,
	}, nil
}

func (p *LoginPage) Render(w http.ResponseWriter, r *http.Request) {
	// Check if user is already logged in
	user := middleware.GetUser(r)
	if user != nil {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	query := r.URL.Query()
	loginType := query.Get("type")

	// Check if this is an IdP login request
	for _, idp := range p.auths {
		if idp.Details().Name == loginType {
			idp.Login(w, r)
			return
		}
	}

	data := LoginPageData{
		AppName:        p.cfg.Name,
		BasePath:       p.basePath,
		ErrorString:    loginErrorString(query),
		HasAdminPrompt: p.cfg.Auth.AdminPassword != "" && p.cfg.Auth.AdminUsername != "",
		HasIdp:         len(p.auths) > 0,
	}

	for _, idp := range p.auths {
		name := idp.Details().Name
		prettyName := strings.ToUpper(name[0:1]) + name[1:]
		data.LoginTypes = append(data.LoginTypes, struct {
			Name        string
			Description string
		}{
			Name:        idp.Details().Name,
			Description: fmt.Sprintf("Sign in with %s", prettyName),
		})
	}

	var buf bytes.Buffer
	if err := p.tpl.ExecuteTemplate(&buf, "login-page", data); err != nil {
		sendError(w, r, err)
		return
	}

	content := template.HTML(buf.String())
	layoutData := types.LayoutData{
		Username:        user.Username,
		Initials:        getInitials(user.Username),
		HasAdmin:        user.Superuser,
		IsAuthenticated: user != nil,
	}
	p.root.RenderRoot(w, r, content, layoutData)
}

func getInitials(username string) string {
	if len(username) == 0 {
		return ""
	}
	parts := strings.Split(username, "@")
	if len(parts[0]) >= 2 {
		return strings.ToUpper(parts[0][0:2])
	}
	return strings.ToUpper(parts[0])
}

func loginErrorString(query map[string][]string) string {
	if len(query["error"]) == 0 {
		return ""
	}

	errorValue := query["error"][0]
	switch errorValue {
	case "invalid_cookie":
		return "Authentication cookie is invalid, log out and retry"
	case "user_not_found":
		if len(query["username"]) > 0 {
			return fmt.Sprintf("User [%s] not found in database. Contact an administrator", query["username"][0])
		}
		return "User not found in database. Contact an administrator"
	case "wrong_credentials":
		return "Invalid username/password"
	default:
		if len(query["message"]) > 0 {
			return fmt.Sprintf("Server error: %s", query["message"][0])
		}
		return fmt.Sprintf("Unknown error: %s", errorValue)
	}
}
