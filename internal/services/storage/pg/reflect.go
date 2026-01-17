package pg

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"reflect"
	"slices"
	"strings"
)

func create[T any](tableName string) string {
	t := reflect.TypeOf(*new(T))
	names := fieldNames(t)
	types := fieldTypes(t)
	columns := make([]string, len(names))
	for i := range names {
		typeStr := map[reflect.Kind]string{
			reflect.Bool:    "boolean",
			reflect.Int16:   "int8",
			reflect.Int32:   "int8",
			reflect.Int64:   "int8",
			reflect.Float64: "float8",
			reflect.Float32: "float8",
		}[types[i].Kind()]
		if typeStr == "" {
			typeStr = "text"
		}
		columns[i] = fmt.Sprintf("%s %s", names[i], typeStr)
	}
	return fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s(%s)", tableName, strings.Join(columns, ","))
}

func put[T any](ctx context.Context, db *sql.DB, item T, tableName string, del bool, ids ...string) error {
	v := reflect.ValueOf(item)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}

	flt := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = v.FieldByName(id).Interface()
		flt[i] = fmt.Sprintf("%s = $%d", id, i+1)
	}

	if del {
		if _, err := db.ExecContext(ctx,
			fmt.Sprintf("DELETE FROM %s WHERE %s", tableName, strings.Join(flt, " AND ")), args...); err != nil {
			return fmt.Errorf("failed to delete: %w", err)
		}
		return nil
	}

	fields := getFields(v.Type())
	columnList := make([]string, len(fields))
	args = make([]any, len(fields))
	placeholders := make([]string, len(fields))
	for i, f := range fields {
		args[i] = v.FieldByName(f.name).Addr().Interface()
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		columnList[i] = f.jsonName
	}
	updateList := make([]string, 0, len(fields))
	for i, c := range columnList {
		if slices.Contains(ids, c) {
			continue
		}
		updateList = append(updateList, fmt.Sprintf("%s = $%d", c, i+1))
	}
	query := fmt.Sprintf(
		"INSERT INTO %s(%s) VALUES(%s) ON CONFLICT (%s) DO UPDATE SET %s",
		tableName,
		strings.Join(columnList, ","),
		strings.Join(placeholders, ","),
		strings.Join(ids, ","),
		strings.Join(updateList, ","),
	)

	if _, err := db.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("failed to upsert: %w", err)
	}

	return nil
}

func scan[T any](ctx context.Context, db *sql.DB, tableName string, filter string, args ...any) ([]T, error) {
	t := reflect.TypeFor[T]()
	columns := fieldNames(t)
	if filter != "" {
		filter = " WHERE " + filter
	}
	query := fmt.Sprintf("SELECT %s FROM %s%s", strings.Join(columns, ","), tableName, filter)
	log.Println(query)
	log.Println(args)
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ret []T
	for rows.Next() {
		k := new(T)
		if err := rows.Scan(scanArgs(reflect.ValueOf(k))...); err != nil {
			return nil, err
		}
		ret = append(ret, *k)
	}
	return ret, rows.Err()
}

func scanArgs(v reflect.Value) []any {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	t := v.Type()
	ret := make([]any, 0, t.NumField())
	for i := range t.NumField() {
		sf := t.Field(i)
		if sf.Name == "Delete" {
			continue
		}
		if sf.Type.Kind() == reflect.Struct {
			ret = append(ret, scanArgs(v.Field(i))...)
			continue
		}
		ret = append(ret, v.Field(i).Addr().Interface())
	}
	return ret
}

type fieldInfo struct {
	name     string
	jsonName string
	typ      reflect.Type
}

var _typeCache = map[reflect.Type][]fieldInfo{}

func getFields(t reflect.Type) []fieldInfo {
	fields, ok := _typeCache[t]
	if ok {
		return fields
	}
	n := t.NumField()
	fields = make([]fieldInfo, 0, n)
	for i := range n {
		sf := t.Field(i)
		if sf.Anonymous {
			fields = append(fields, getFields(sf.Type)...)
			continue
		}
		jsonTag := strings.Split(sf.Tag.Get("json"), ",")
		name := jsonTag[0]
		if name == "" {
			name = sf.Name
		}
		if name == "delete" {
			continue
		}
		fields = append(fields, fieldInfo{name: sf.Name, jsonName: name, typ: sf.Type})
	}
	_typeCache[t] = fields
	return fields
}

func fieldTypes(t reflect.Type) []reflect.Type {
	fields := getFields(t)
	types := make([]reflect.Type, len(fields))
	for i, f := range fields {
		types[i] = f.typ
	}
	return types
}

func fieldNames(t reflect.Type) []string {
	fields := getFields(t)
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.jsonName
	}
	return names
}
