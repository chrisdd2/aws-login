package templates

import (
	"embed"
	"html/template"
	"io"

	"github.com/chrisdd2/aws-login/aws"
)

//go:embed static webfonts
var Static embed.FS

//go:embed *.html
var pages embed.FS
var pagesTmpls = template.Must(template.ParseFS(pages, "*.html"))

type Navbar struct {
	AppName  string
	Username string
	HasAdmin bool
}

type LoginData struct {
	HasAdminPrompt bool
	AppName        string
	ErrorString    string
	LoginType      []struct {
		Name string
		Desc string
	}
}

func LoginTemplate(w io.Writer, data LoginData) error {
	return pagesTmpls.ExecuteTemplate(w, "login.html", data)
}

type Role struct {
	AccountId      string
	AccountName    string
	RoleName       string
	HasCredentials bool
	HasConsole     bool
}
type RolesData struct {
	Navbar
	Roles []Role
}

type Account struct {
	AccountName  string
	AccountId    string
	UpdateStatus string
	HasStack     bool
	HasDeploy    bool
}

type AdminData struct {
	Navbar
	Accounts []Account
}
type WatchData struct {
	Navbar
	Events []aws.StackEvent
}

func RolesTemplate(w io.Writer, data RolesData) error {
	return pagesTmpls.ExecuteTemplate(w, "roles.html", data)
}

func AdminTemplate(w io.Writer, data AdminData) error {
	return pagesTmpls.ExecuteTemplate(w, "admin.html", data)
}
func WatchTemplate(w io.Writer, data WatchData) error {
	return pagesTmpls.ExecuteTemplate(w, "watch.html", data)
}
