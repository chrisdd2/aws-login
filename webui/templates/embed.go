package templates

import (
	"embed"
	"errors"
	"html/template"
	"io"
	"io/fs"
	"log"

	"github.com/chrisdd2/aws-login/auth"
	"github.com/chrisdd2/aws-login/storage"
	"github.com/labstack/echo/v4"
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

type Role struct {
	Arn       string
	AccountId string
	Name      string
	CanGrant  bool
	CanAssume bool
}

type templateData struct {
	Title           string
	LogoutPath      string
	ProfilePath     string
	LoginPath       string
	Logged          bool
	Users           []storage.User
	User            *auth.UserInfo
	Accounts        []storage.Account
	Permissions     []storage.Permission
	UserPermissions []struct {
		Permission storage.Permission
		User       storage.User
	}
	HasNext     bool
	StartToken  string
	HasPrevious bool
	Roles       []Role
	StackId     string

	Menu []MenuItem
}

func (t *templateData) Account() storage.Account {
	return t.Accounts[0]
}
func (t *templateData) Role() Role {
	return t.Roles[0]
}

type MenuItem struct {
	Label string
	Path  string
}

func TemplateData(user *auth.UserInfo, title string) *templateData {
	d := templateData{
		Title:       title,
		LoginPath:   "/login/",
		LogoutPath:  "/logout/",
		ProfilePath: "/profile/",
		Menu: []MenuItem{
			{Label: "Accounts", Path: "/accounts/"},
		},
		User: user,
	}
	if d.User != nil {
		d.Logged = true
		if d.User.Superuser {
			d.Menu = append(d.Menu, MenuItem{
				Label: "Admin", Path: "/admin",
			}, MenuItem{Label: "Users", Path: "/users"})
		}
	}
	return &d
}

type EchoRenderer struct{}

func (t *EchoRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	c.Response().Header().Add("Content-Type", "text/html; charset=utf-8")
	tmpl, ok := templates[name]
	if !ok {
		return ErrTemplateNotExist
	}
	return tmpl.ExecuteTemplate(w, name, data)
}
