package templates

import (
	"embed"
	"html/template"
	"io"
)

//go:embed *.html
var pages embed.FS
var pagesTmpls = template.Must(template.ParseFS(pages, "*.html"))

type Navbar struct {
	Username string
	HasAdmin bool
}

type LoginData struct {
	ErrorString string
	LoginType   []struct {
		Name string
		Desc string
	}
}

func LoginTemplate(w io.Writer, data LoginData) error {
	return pagesTmpls.ExecuteTemplate(w, "login.html", data)
}

type Role struct {
	AccountId      int
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
	AccountName string
	AccountId   int
}

type AdminData struct {
	Navbar
	Accounts []Account
}

func RolesTemplate(w io.Writer, data RolesData) error {
	return pagesTmpls.ExecuteTemplate(w, "roles.html", data)
}

func AdminTemplate(w io.Writer, data AdminData) error {
	return pagesTmpls.ExecuteTemplate(w, "admin.html", data)
}
