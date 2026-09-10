package main

import (
	"embed"
	"html/template"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

// templateFuncs are available to every page template. Add helpers here as
// new pages need them.
var templateFuncs = template.FuncMap{
	"join": func(items []string, sep string) string { return strings.Join(items, sep) },
}

// templates holds all parsed page templates, keyed by "define" name.
// Add new pages by dropping a template file in templates/ and defining
// a {{define "name"}} block in it; ExecuteTemplate(w, "name", data) picks
// it up automatically.
var templates = template.Must(template.New("").Funcs(templateFuncs).ParseFS(templateFS, "templates/*.html"))
