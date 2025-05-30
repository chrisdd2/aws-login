package templates

import (
	"embed"
	"errors"
	"html/template"
	"io/fs"
	"log"
	"net/http"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/storage"
)

const layoutFile = "layout.html"

var (
	//go:embed *.html
	embeddedFiles       embed.FS
	templates           map[string]*template.Template
	ErrTemplateNotExist error = errors.New("template doesn't exist")
)

func init() {
	templates = map[string]*template.Template{}
	files, err := fs.Glob(embeddedFiles, "*.html")
	if err != nil {
		panic(err.Error())
	}
	for _, file := range files {
		log.Println(file)
		if file == layoutFile {
			continue
		}
		t := template.Must(template.ParseFS(embeddedFiles, layoutFile))
		templates[file] = template.Must(t.ParseFS(embeddedFiles, file))
	}
}

func RenderPage(w http.ResponseWriter, name string, data any) error {
	w.Header().Add("Content-Type", "text/html; charset=utf-8")
	tmpl, ok := templates[name]
	if !ok {
		return ErrTemplateNotExist
	}
	return tmpl.ExecuteTemplate(w, name, data)
}

type Role struct {
	Arn       string
	AccountId string
	Name      string
}

type templateData struct {
	Title       string
	LogoutPath  string
	ProfilePath string
	LoginPath   string
	Logged      bool
	User        *auth.UserInfo
	Accounts    []storage.Account
	HasNext     bool
	StartToken  string
	HasPrevious bool
	Roles       []Role

	Menu []MenuItem
}

type MenuItem struct {
	Label string
	Path  string
}

func TemplateData(user *auth.UserInfo, title string) *templateData {
	d := templateData{
		Title:       title,
		LoginPath:   "/login",
		LogoutPath:  "/logout",
		ProfilePath: "/profile",
		Menu: []MenuItem{
			{Label: "Accounts", Path: "/accounts"},
		},
		User: user,
	}
	if d.User != nil && d.User.Superuser {
		d.Menu = append(d.Menu, MenuItem{
			Label: "Admin", Path: "/admin",
		})
		d.Logged = true
	}
	return &d
}
