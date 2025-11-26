//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"io"
	"log"
	"maps"
	"os"
	"slices"
	"strings"
	"text/template"
)

const tmpl = `
{{ $root := .}}

package {{ .Package }}
import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"iter"
	"os"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
)

var ({{range .Objects}}
	Err{{.TypeName}}NotFound = errors.New("{{.TypeName}} does not exist")
	{{- end}}
)

const (
	pageSize = 50
)

type Service interface {
	{{- range .Objects }}
	{{- $parent:=. -}}
	{{- $v := .Name | lower -}}
	{{if and ( ne .IdField "") (not .SkipGetFunc ) }}
	Get{{.Name}}(ctx context.Context, id string) (*{{.TypeName}}, error)
	Get{{.Name}}s(ctx context.Context, id ...string) ([]*{{.TypeName}}, error)
	{{end}}
	{{- if gt (.ListConditionals | len) 0 -}}
	List{{.Name}}s(ctx context.Context {{range .ListConditionals}}, {{.Name | makeParam}} {{.Type}} {{end}},nextToken *string ) (iter.Seq[*{{.TypeName}}], *string, error)
	{{- else -}}
	List{{.Name}}s(ctx context.Context, nextToken *string) (iter.Seq[*{{.TypeName}}], *string, error)
	{{- end }}
	Put{{.Name}}(ctx context.Context, {{$v}} *{{.TypeName}}, del bool) (*{{.TypeName}}, error)
	{{range .LookupFields }}
	{{- $first := index .Fields 0 -}}
	{{- $rest := slice .Fields 1 -}}
	{{.FunctionName}}(ctx context.Context, {{$first.Name | makeParam }} {{ $first.Type}} {{ range $rest }}, {{ .Name | makeParam}} {{.Type}} {{end}} )({{ if .ExistsOnly }} bool {{else }} *{{$parent.TypeName}} {{end}}, error)
	{{ end}}
	{{- end }}
	Close() error
}

// Simple memory based implementation of the storage backend
//
// Persists data to a json file.
// Updates on every "write" action
//
// Performance is not great and not a priority
type {{.StructName}} struct {
	writeLock sync.Mutex
	fileName  string

	// fields to serialize to the actual file
	jsonSerializableFields
}

type jsonSerializableFields struct {
	LastUpdate         time.Time
	{{- range .Objects}}
	{{.FieldName}}          []*{{.TypeName}}    {{$root.Backtick}}json:"{{ .FieldName | lower }},omitempty"{{$root.Backtick}}
	{{- end}}
}

func New{{.StructName}}(fileName string) (Service, error) {
	ret := &{{.StructName}}{
		fileName:               fileName,
		jsonSerializableFields: jsonSerializableFields{},
	}
	f, err := os.Open(fileName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ret, nil
		}
		return nil, err
	}
	defer f.Close()
	return ret, json.NewDecoder(f).Decode(&ret.jsonSerializableFields)
}

func (j *jsonSerializableFields) sortSlices() {
	{{- range .Objects}}
	j.{{.FieldName}} = slices.SortedFunc(slices.Values(j.{{.FieldName}}), func(u1, u2 *{{.TypeName}}) int { return cmp.Compare(u1.{{.IdField}}, u2.{{.IdField}}) })
	{{- end}}
}

func (j *{{.StructName}}) lock() {
	j.writeLock.Lock()
}
func (j *{{.StructName}}) unlock() error {
	defer j.writeLock.Unlock()
	f, err := os.Create(j.fileName)
	if err != nil {
		return err
	}
	defer f.Close()
	// make it readable
	j.sortSlices()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	j.LastUpdate = time.Now().UTC()
	return enc.Encode(j.jsonSerializableFields)
}

func (j *{{.StructName}}) Close() error {
	j.lock()
	// heh
	return j.unlock()
}

func parsePaginationToken(token *string, total int, pageSize int) (startPos, endPos int, nextToken *string, err error) {
	if token == nil {
		return 0, total, nil, nil
	}
	num, err := strconv.Atoi(*token)
	if err != nil {
		return -1, -1, nil, err
	}
	startPos = num
	endPos = num + pageSize
	if endPos > total {
		endPos = total
	} else {
		t := strconv.Itoa(endPos)
		nextToken = &t
	}
	return startPos, endPos, nextToken, nil
}

func matchOrEmpty(a, b string) bool {
	return b == "" || a == b
}


{{- $structName:= .StructName -}}
{{ range .Objects -}}
{{$parent :=.}}
{{if and ( ne .IdField "") (not .SkipGetFunc ) }}
func (j *{{$structName}}) Get{{.Name}}(ctx context.Context, id string) (*{{.TypeName}}, error) {
	for _, v := range j.{{.FieldName}} {
		if id ==  v.{{.IdField}} {
			return v,nil
		}
	}
	return nil, Err{{.TypeName}}NotFound
}
func (j *{{$structName}}) Get{{.Name}}s(ctx context.Context, id ...string) ([]*{{.TypeName}}, error) {
	ret := []*{{.TypeName}}{}
	for _, v := range j.{{.FieldName}} {
		for _, z := range id {
			if z ==  v.{{.IdField}} {
				ret = append(ret, v)
				break
			}
		}
	}
	return ret, nil
}
{{end}}
{{- if gt (.ListConditionals | len) 0 -}}
func (j *{{$structName}}) List{{.Name}}s(ctx context.Context {{range .ListConditionals}}, {{.Name | makeParam}} {{.Type}} {{end}},nextToken *string ) (iter.Seq[*{{.TypeName}}], *string, error) {
{{- else -}}
func (j *{{$structName}}) List{{.Name}}s(ctx context.Context, nextToken *string) (iter.Seq[*{{.TypeName}}], *string, error) {
{{- end -}}
	startPos, endPos, nextToken, err := parsePaginationToken(nextToken, len(j.{{.FieldName}}), pageSize)
	if err != nil {
		return nil, nil, err
	}
	return func(yield func(*{{.TypeName}}) bool) {
		for i := startPos; i < endPos; i++ {
			item := j.{{.FieldName}}[i]
			{{- if gt ( .ListConditionals | len) 0 }}
			{{- $first := index .ListConditionals 0 }}
			{{- $rest := slice .ListConditionals 1 }}
			if !(matchOrEmpty({{$first.Name |makeParam }},item.{{$first.Name }}) {{range $rest}} && matchOrEmpty({{.Name | makeParam}},item.{{.Name}}) {{end}}) {
				continue
			}
			{{end}}
			if !yield(item) {
				break
			}
		}
	}, nextToken, nil
}

{{ $v := .Name | lower}}
func (j *{{$structName}}) Put{{.Name}}(ctx context.Context, {{$v}} *{{.TypeName}}, del bool) (*{{.TypeName}}, error) {
{{- $first := index .CompareFields 0 }}
{{- $rest := slice .CompareFields 1 }}
	j.lock()
	defer j.unlock()
	if del {
		j.{{.FieldName}} = slices.DeleteFunc(j.{{.FieldName}}, func(v *{{.TypeName}}) bool {
			return {{$v}}.{{$first}} == v.{{$first}} {{range $rest }} && {{$v}}.{{.}} == v.{{.}}{{end}}
		})
		return {{$v}}, nil
	}
	idx := slices.IndexFunc(j.{{.FieldName}}, func(v *{{.TypeName}}) bool {
		return {{$v}}.{{$first}} == v.{{$first}} {{range $rest }} && {{$v}}.{{.}} == v.{{.}}{{end}}
	})
	if idx != -1 {
		{{$v}}.{{.IdField}} = j.{{.FieldName}}[idx].{{.IdField}}
		j.{{.FieldName}}[idx] = {{$v}}
	} else {
		if {{$v}}.{{.IdField}} == "" {
			{{$v}}.{{.IdField}} = uuid.NewString()
		}
		j.{{.FieldName}} = append(j.{{.FieldName}}, {{$v}})
	}
	return {{$v}}, nil
}

{{range .LookupFields -}}
{{- $first := index .Fields 0 -}}
{{- $rest := slice .Fields 1 -}}
func (j *{{$structName}}) {{.FunctionName}}(ctx context.Context, {{$first.Name | makeParam }} {{ $first.Type}} {{ range $rest }}, {{ .Name | makeParam}} {{.Type}} {{end}} )({{ if .ExistsOnly }} bool {{else }} *{{$parent.TypeName}} {{end}}, error)  {
	for _, v := range j.{{$parent.FieldName}} {
		if v.{{$first.Name}} == {{$first.Name | makeParam}} {{ range $rest}} && v.{{.Name}} == {{.Name | makeParam}}{{end}} {
			{{- if .ExistsOnly }}
			return true,nil
			{{- else}}
			return v,nil
			{{- end}}
		}
	}
	{{- if .ExistsOnly }}
	return false,nil
	{{- else}}
	return nil, Err{{$parent.TypeName}}NotFound
	{{- end}}
}
{{end -}}
{{end }}`

type Field struct {
	Name string
	Type string
}
type LookupField struct {
	FunctionName string
	Fields       []Field
	ExistsOnly   bool
}

type Object struct {
	Name             string
	FieldName        string
	TypeName         string
	IdField          string
	SkipGetFunc      bool
	CompareFields    []string
	ListConditionals []Field
	LookupFields     []*LookupField
}

type TemplateVars struct {
	Package    string
	StructName string
	Backtick   string
	Objects    []Object
}

func main() {
	fmt.Printf("Running %s go on %s\n", os.Args[0], os.Getenv("GOFILE"))

	parsedTemplate := template.Must(template.New("").Funcs(template.FuncMap{
		"lower": strings.ToLower,
		"makeParam": func(param string) string {
			v := strings.ToLower(param[0:1]) + param[1:]
			if token.Lookup(v) != token.IDENT {
				v = v + "_"
			}
			return v
		},
	}).Parse(tmpl))

	fset := token.NewFileSet()
	filename := os.Getenv("GOFILE")
	file, err := parser.ParseFile(fset, filename, nil, parser.ParseComments)
	if err != nil {
		log.Fatalln(err)
	}

	objects := []Object{}

	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			return true
		}
		typeDecl, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		structDecl, ok := typeDecl.Type.(*ast.StructType)
		if !ok {
			return true
		}
		typeName := typeDecl.Name.Name
		object := Object{
			Name:      typeName,
			TypeName:  typeName,
			FieldName: typeName + "s",
		}

		lookups := map[string]*LookupField{}
		for _, field := range structDecl.Fields.List {
			tags := parseTagValue(field.Tag.Value)
			sgTag := tags["sg"]
			if len(sgTag) == 0 {
				continue
			}
			name := field.Names[0].Name
			fieldType := fmt.Sprint(field.Type)
			if mapHasKey(sgTag, "id") {
				if object.IdField != "" {
					fmt.Printf("duplicate id key found for struct %s [%s,%s]", object.Name, object.IdField, name)
					return true
				}
				object.IdField = name
			}
			if mapHasKey(sgTag, "skipget") {
				object.SkipGetFunc = true
			}
			lookup := sgTag["lookup"]
			functionName := sgTag["functionName"]
			existsOnly := mapHasKey(sgTag, "existsOnly")
			if lookup != "" {
				lookupField, ok := lookups[lookup]
				if !ok {
					lookupField = &LookupField{}
					lookups[lookup] = lookupField
				}
				lookupField.Fields = append(lookupField.Fields, Field{Name: name, Type: fieldType})
				if functionName != "" {
					lookupField.FunctionName = functionName
				}
				if existsOnly {
					lookupField.ExistsOnly = true
				}
			}
			if mapHasKey(sgTag, "list") {
				object.ListConditionals = append(object.ListConditionals, Field{Name: name, Type: fieldType})
			}
			if mapHasKey(sgTag, "cmp") {
				object.CompareFields = append(object.CompareFields, name)
			}
		}
		// validate lookups
		lookupsList := slices.Collect(maps.Values(lookups))
		for _, lookup := range lookupsList {
			if lookup.FunctionName == "" {
				fmt.Printf("no function name for lookup with fields %v\n", lookup.Fields)
				return true
			}
			if len(lookup.Fields) == 0 {
				fmt.Printf("no fields name for lookup with name %s\n", lookup.FunctionName)
				return true
			}
		}
		object.LookupFields = lookupsList
		if len(object.CompareFields) == 0 {
			object.CompareFields = append(object.CompareFields, object.IdField)
		}
		objects = append(objects, object)
		return true
	})

	buf := bytes.Buffer{}
	if err := parsedTemplate.Execute(&buf, TemplateVars{
		StructName: "JsonBackend",
		Objects:    objects,
		Backtick:   "`",
		Package:    os.Getenv("GOPACKAGE"),
	}); err != nil {
		log.Fatalln(err)
	}

	outfilename := fmt.Sprintf("%s_json.generated.go", strings.TrimSuffix(filename, ".go"))
	outfile, err := os.Create(outfilename)
	if err != nil {
		log.Fatalln(err)
	}
	defer outfile.Close()

	// print with gofmt
	if err := prettyPrint(&buf, outfile); err != nil {
		log.Println(err)
		io.Copy(outfile, &buf)
	}

	// from placerholder generator, seems useful
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	fmt.Printf("  cwd = %s\n", cwd)
	fmt.Printf("  os.Args = %#v\n", os.Args)

	vals := os.Environ()
	for _, k := range vals {
		parts := strings.Split(k, "=")
		if strings.HasPrefix(parts[0], "GO") {
			fmt.Println("  ", parts[0], "=", parts[1])
		}
	}
}
func parseTagValue(tag string) map[string]map[string]string {
	tag = strings.Trim(tag, "`")
	ret := map[string]map[string]string{}
	for item := range strings.SplitSeq(tag, " ") {
		tagType, tagValue, _ := strings.Cut(item, ":")
		tagValue = strings.Trim(tagValue, "\"")
		argsMap := map[string]string{}
		for _, arg := range strings.Split(tagValue, ",") {
			parts := strings.Split(arg, "=")
			v := ""
			if len(parts) > 1 {
				v = parts[1]
			}
			argsMap[parts[0]] = v
		}
		ret[tagType] = argsMap
	}
	return ret
}

func mapHasKey[K comparable, V any](m map[K]V, k K) bool {
	_, e := m[k]
	return e
}

func prettyPrint(in io.Reader, out io.Writer) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "file", in, parser.ParseComments)
	if err != nil {
		return err
	}
	return format.Node(out, fset, file)
}
