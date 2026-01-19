package pg

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
)

func create[T any](tableName string) string {
	t := reflect.TypeOf(*new(T))
	names := fieldNames(t)
	types := fieldTypes(t)
	columns := make([]string, len(names))
	for i := range names {
		typeStr := map[reflect.Kind]string{
			reflect.Bool:    "boolean",
			reflect.Int16:   "int2",
			reflect.Int32:   "int4",
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

	fields := getFields(v.Type())
	idJsonNames := []string{}
	args := []any{}
	for _, id := range ids {
		name := id
		for _, f := range fields {
			if id == f.name {
				name = f.jsonName
				break
			}
		}
		idJsonNames = append(idJsonNames, name)
		args = append(args, v.FieldByName(id).Interface())
	}
	flt := make([]string, len(ids))
	for i, id := range idJsonNames {
		flt[i] = fmt.Sprintf("%s = $%d", id, i+1)
	}

	if del {
		q := fmt.Sprintf("DELETE FROM %s WHERE %s", tableName, strings.Join(flt, " AND "))
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			return fmt.Errorf("failed to delete: %w", err)
		}
		return nil
	}

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
		strings.Join(idJsonNames, ","),
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
		if strings.ToLower(sf.Name) == "delete" {
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

var _typeCache = sync.Map{}

func getFields(t reflect.Type) []fieldInfo {
	val, ok := _typeCache.Load(t)
	if ok {
		return val.([]fieldInfo)
	}
	n := t.NumField()
	fields := make([]fieldInfo, 0, n)
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
		if strings.ToLower(name) == "delete" {
			continue
		}
		fields = append(fields, fieldInfo{name: sf.Name, jsonName: name, typ: sf.Type})
	}
	_typeCache.Store(t, fields)
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
