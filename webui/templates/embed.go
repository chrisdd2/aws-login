package templates

import (
	"embed"
	"encoding/json"
	"html/template"
	"io"

	"github.com/chrisdd2/aws-login/aws"
	"github.com/chrisdd2/aws-login/services/storage"
)

//go:embed static webfonts
var Static embed.FS

//go:embed *.html
var pages embed.FS

func jsonFunc(v any) string {
	data, _ := json.MarshalIndent(v, "", "  ")
	return string(data)
}

var pagesTmpls = template.Must(template.New("").Funcs(template.FuncMap{
	"json": jsonFunc,
}).ParseFS(pages, "*.html"))

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

type AccountsData struct {
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

func AccountsTemplate(w io.Writer, data AccountsData) error {
	return pagesTmpls.ExecuteTemplate(w, "accounts.html", data)
}
func WatchTemplate(w io.Writer, data WatchData) error {
	return pagesTmpls.ExecuteTemplate(w, "watch.html", data)
}

type ConfigurationData struct {
	Navbar
	Store *storage.InMemoryStore
}

func ConfigurationTemplate(w io.Writer, data ConfigurationData) error {
	return pagesTmpls.ExecuteTemplate(w, "config.html", data)
}
