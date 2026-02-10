package types

import (
	"html/template"
	"net/http"
)

// LayoutRenderer is implemented by RootPage to provide layout wrapping
type LayoutRenderer interface {
	RenderRoot(w http.ResponseWriter, r *http.Request, content template.HTML, data LayoutData)
}

// LayoutData contains data for rendering the layout
type LayoutData struct {
	AppName         string
	Username        string
	Initials        string
	HasAdmin        bool
	IsAuthenticated bool
	CurrentPath     string
	IsHtmxRequest   bool
	Content         template.HTML
}
