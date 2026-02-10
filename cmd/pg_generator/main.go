package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
)

var (
	tableName = flag.String("table", "", "PostgreSQL table name")
	output    = flag.String("output", "", "Output file (default: generated.<struct_name>.go)")
)

func structLine() int {
	targetLine, _ := strconv.ParseInt(os.Getenv("GOLINE"), 10, 64)
	targetLine++
	return int(targetLine)
}

func main() {
	flag.Parse()
	if *tableName == "" {
		log.Fatal("-table flag is required")
	}

	goFile := os.Getenv("GOFILE")

	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, goFile, nil, parser.ParseComments)
	if err != nil {
		log.Fatalf("Error parsing file: %v", err)
	}
	// Find the struct at the line after the directive (go:generate is on GOLINE, struct is on GOLINE+1)
	targetLine := structLine()
	var si *StructInfo
	ast.Inspect(node, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.TypeSpec:
			linePos := fset.Position(x.Pos()).Line
			if x.Name.Name != "" && linePos == targetLine {
				if st, ok := x.Type.(*ast.StructType); ok {
					si = parseStruct(x.Name.Name, st)
				}
			}
		}
		return true
	})

	if si == nil {
		log.Fatalf("Struct not found at line %d", targetLine)
	}

	structName := si.Name

	data := struct {
		Package string
		Table   string
		Struct  StructInfo
	}{
		Package: node.Name.Name,
		Table:   *tableName,
		Struct:  *si,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		log.Fatalf("Error executing template: %v", err)
	}

	out := os.Stdout
	outPath := *output
	if outPath == "" {
		// Default output: same directory as source, generated.<struct_name>.go
		dir := filepath.Dir(goFile)
		outPath = filepath.Join(dir, fmt.Sprintf("generated.%s.go", strings.ToLower(structName)))
	}

	out, err = os.Create(outPath)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer out.Close()

	if _, err := out.Write(buf.Bytes()); err != nil {
		log.Fatalf("Error writing output: %v", err)
	}
}

type StructInfo struct {
	Name         string
	Fields       []FieldInfo
	IDFields     []FieldInfo
	FilterFields []FieldInfo
}

type FieldInfo struct {
	Name       string
	Type       string
	ColumnName string
	IsID       bool
	IsFilter   bool
}

func parseStruct(name string, st *ast.StructType) *StructInfo {
	var si StructInfo
	si.Name = name

	for _, field := range st.Fields.List {
		if len(field.Names) == 0 {
			continue
		}
		fieldName := field.Names[0].Name

		tag := ""
		if field.Tag != nil {
			tag = field.Tag.Value
		}

		isID, isFilter, colName := parseTag(tag, fieldName)

		fi := FieldInfo{
			Name:       fieldName,
			ColumnName: colName,
			IsID:       isID,
			IsFilter:   isFilter,
		}

		switch t := field.Type.(type) {
		case *ast.Ident:
			fi.Type = t.Name
		case *ast.ArrayType:
			fi.Type = "[]" + typeString(t.Elt)
		case *ast.StarExpr:
			fi.Type = "*" + typeString(t.X)
		default:
			fi.Type = typeString(field.Type)
		}

		si.Fields = append(si.Fields, fi)
		if isID {
			si.IDFields = append(si.IDFields, fi)
		}
		if isFilter {
			si.FilterFields = append(si.FilterFields, fi)
		}
	}

	if len(si.Fields) == 0 {
		return nil
	}
	return &si
}

func tagToDict(tagString string) map[string][]string {
	ret := map[string][]string{}
	for tag := range strings.SplitSeq(tagString, " ") {
		tagName, tagValue, found := strings.Cut(tag, ":")
		if !found {
			continue
		}
		tagName = strings.TrimSpace(tagName)
		tagValue = strings.Trim(tagValue, "\" `")
		ret[tagName] = strings.Split(tagValue, ",")
	}
	return ret
}

func parseTag(tag, fieldName string) (isID, isFilter bool, columnName string) {
	columnName = toSnakeCase(fieldName)

	tags := tagToDict(tag)
	if len(tags) == 0 {
		return false, false, columnName
	}

	dbTag := tags["db"]
	for i, v := range dbTag {
		switch v {
		case "id":
			isID = true
		case "filter":
			isFilter = true
		default:
			if i == 0 {
				columnName = v
			}
		}
	}
	return isID, isFilter, columnName
}

func typeString(t ast.Expr) string {
	switch x := t.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.StarExpr:
		return "*" + typeString(x.X)
	case *ast.ArrayType:
		return "[]" + typeString(x.Elt)
	case *ast.SelectorExpr:
		return typeString(x.X) + "." + x.Sel.Name
	default:
		return fmt.Sprintf("%T", t)
	}
}

func toSnakeCase(name string) string {
	if name == "ID" {
		return "id"
	}
	// Handle special case: acronyms at the end (e.g., UserID -> user_id)
	if strings.HasSuffix(name, "ID") && len(name) > 2 {
		name = name[:len(name)-1] + "d"
	}
	var result strings.Builder
	for i, c := range name {
		if c >= 'A' && c <= 'Z' {
			if i > 0 && result.Len() > 0 {
				result.WriteByte('_')
			}
			result.WriteByte(byte(c + 32))
		} else {
			result.WriteByte(byte(c))
		}
	}
	return result.String()
}

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"toLower": strings.ToLower,
	"add":     func(a, b int) int { return a + b },
	"inc":     func(i int) int { return i + 1 },
}).Parse(`// Code generated by pg_generator. DO NOT EDIT.

package {{.Package}}

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"iter"
	"strings"
)

// Generated CRUD operations for {{.Table}}

const findLimit{{.Struct.Name}} = 50

// {{.Struct.Name}}Filter represents filter options for {{.Struct.Name}} queries
type {{.Struct.Name}}Filter struct {
{{- range .Struct.FilterFields}}
	{{.Name}} *{{.Type}}
{{- end}}
}


// decodeToken decodes a base64-encoded offset token
func (a *{{.Struct.Name}}) decodeToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return 0, err
	}
	var offset int
	fmt.Sscanf(string(data), "%d", &offset)
	return offset, nil
}

{{if .Struct.IDFields}}
// Get retrieves a {{.Struct.Name}} by ID
func (a *{{.Struct.Name}}) Get(ctx context.Context, db *sql.DB{{range .Struct.IDFields}}, {{.Name | toLower}} {{.Type}}{{end}}) error {
{{- $idCount := len .Struct.IDFields}}
	var whereClauses []string
	var args []any
{{- range $i, $f := .Struct.IDFields}}
	whereClauses = append(whereClauses, fmt.Sprintf("%s = $%d", "{{$f.ColumnName}}", {{add $i 1}}))
	args = append(args, {{$f.Name | toLower}})
{{- end}}

	q := fmt.Sprintf("SELECT {{range $i, $f := .Struct.Fields}}{{if gt $i 0}}, {{end}}{{$f.ColumnName}}{{end}} FROM {{.Table}} WHERE %s", strings.Join(whereClauses, " AND "))

	return db.QueryRowContext(ctx, q, args...).Scan(
{{- range .Struct.Fields}}
		&a.{{.Name}},
{{- end}}
	)
}

// Delete deletes a {{.Struct.Name}} by ID
func (a *{{.Struct.Name}}) Delete(ctx context.Context, db *sql.DB{{range .Struct.IDFields}}, {{.Name | toLower}} {{.Type}}{{end}}) error {
{{- $idCount := len .Struct.IDFields}}
	var whereClauses []string
	var args []any
{{- range $i, $f := .Struct.IDFields}}
	whereClauses = append(whereClauses, fmt.Sprintf("%s = $%d", "{{$f.ColumnName}}", {{add $i 1}}))
	args = append(args, {{$f.Name | toLower}})
{{- end}}

	q := fmt.Sprintf("DELETE FROM {{.Table}} WHERE %s", strings.Join(whereClauses, " AND "))
	_, err := db.ExecContext(ctx, q, args...)
	return err
}
{{end}}

// Insert inserts a {{.Struct.Name}} into the database
func (a *{{.Struct.Name}}) Insert(ctx context.Context, db *sql.DB) error {
	columns := []string{ {{range .Struct.Fields}}"{{.ColumnName}}",{{end}} }
	placeholders := make([]string, len(columns))
	for i := range columns {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
	}

	q := fmt.Sprintf("INSERT INTO {{.Table}} (%s) VALUES (%s)", strings.Join(columns, ", "), strings.Join(placeholders, ", "))

	_, err := db.ExecContext(ctx, q,
{{- range .Struct.Fields}}
		a.{{.Name}},
{{- end}}
	)
	return err
}

// Update updates a {{.Struct.Name}} in the database
func (a *{{.Struct.Name}}) Update(ctx context.Context, db *sql.DB) error {
{{- if .Struct.IDFields}}
{{- $idFields := .Struct.IDFields }}
{{- $fieldCount := len .Struct.Fields }}
{{- $idCount := len $idFields }}
	setClauses := make([]string, 0, {{$fieldCount}})
	args := make([]any, 0, {{add $fieldCount $idCount}})
{{- range $i, $f := .Struct.Fields}}
{{- if not $f.IsID}}
	setClauses = append(setClauses, fmt.Sprintf("%s = $%d", "{{$f.ColumnName}}", {{inc $i}}))
	args = append(args, a.{{$f.Name}})
{{- end}}
{{- end}}

	idArgs := make([]any, 0, {{$idCount}})
{{- range $i, $f := $idFields}}
	idArgs = append(idArgs, a.{{$f.Name}})
{{- end}}
	args = append(args, idArgs...)

	whereClauses := make([]string, 0, {{$idCount}})
{{- range $i, $f := $idFields}}
{{- $colIdx := add $fieldCount $i}}
	whereClauses = append(whereClauses, fmt.Sprintf("%s = $%d", "{{$f.ColumnName}}", {{inc $colIdx}}))
{{- end}}

	q := fmt.Sprintf("UPDATE {{.Table}} SET %s WHERE %s", strings.Join(setClauses, ", "), strings.Join(whereClauses, " AND "))
	_, err := db.ExecContext(ctx, q, args...)
	return err
{{- else}}
	return fmt.Errorf("Update requires at least one field with db:id tag")
{{- end}}
}

// List returns all {{.Struct.Name}} rows
func (a *{{.Struct.Name}}) List(ctx context.Context, db *sql.DB) iter.Seq2[*{{.Struct.Name}}, error] {
	return func(yield func(*{{.Struct.Name}}, error) bool) {
		q := fmt.Sprintf("SELECT {{range $i, $f := .Struct.Fields}}{{if gt $i 0}}, {{end}}{{$f.ColumnName}}{{end}} FROM {{.Table}} ORDER BY 1")
		rows, err := db.QueryContext(ctx, q)
		if err != nil {
			yield(nil, err)
			return
		}
		defer rows.Close()

		for rows.Next() {
			var item {{.Struct.Name}}
			if err := rows.Scan(
{{- range .Struct.Fields}}
				&item.{{.Name}},
{{- end}}
			); err != nil {
				if !yield(nil, err) {
					return
				}
				continue
			}
			if !yield(&item, nil) {
				return
			}
		}
	}
}

// Find returns {{.Struct.Name}} rows matching the filter with pagination
func (a *{{.Struct.Name}}) Find(ctx context.Context, db *sql.DB, filter {{.Struct.Name}}Filter, token string) ([]*{{.Struct.Name}},*string, error) {
	offset, err := a.decodeToken(token)
	if err != nil {
		return nil, nil, fmt.Errorf("decode token: %w", err)
	}

	var conditions []string
	var args []any
{{- range $f := .Struct.FilterFields}}
	if filter.{{$f.Name}} != nil {
		args = append(args, *filter.{{$f.Name}})
		conditions = append(conditions, fmt.Sprintf("%s = $%d", "{{$f.ColumnName}}", len(args)))
	}
{{- end}}

	where := ""
	if len(conditions) > 0 {
		where = " WHERE " + strings.Join(conditions, " AND ")
	}

	q := fmt.Sprintf("SELECT {{range $i, $f := .Struct.Fields}}{{if gt $i 0}}, {{end}}{{$f.ColumnName}}{{end}} FROM {{.Table}}%s ORDER BY 1 OFFSET %d LIMIT %d", where, offset, findLimit{{.Struct.Name}})

	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("query: %w", err)
	}
	defer rows.Close()

	var items []*{{.Struct.Name}}
	for rows.Next() {
		var item {{.Struct.Name}}
		if err := rows.Scan(
{{- range .Struct.Fields}}
			&item.{{.Name}},
{{- end}}
		); err != nil {
			return nil, nil, fmt.Errorf("scan: %w", err)
		}
		items = append(items, &item)
	}

	nextToken := ""
	if len(items) == findLimit{{.Struct.Name}} {
		nextOffset := offset + findLimit{{.Struct.Name}}
		nextToken = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", nextOffset)))
	}

	return items, &nextToken, nil
}
`))
