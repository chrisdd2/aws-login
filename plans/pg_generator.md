# pg_generator - Go ORM Generator for PostgreSQL

## Context
Create a `go:generate`-compatible ORM generator that parses Go structs and generates CRUD methods. Generated code lives in the same package as the struct.

## Tags
- `db:id` - Primary key field(s) (supports composite keys)
- `db:filter` - Filterable field for Find queries
- `db:id,filter` - Both ID and filterable
- `db:"column_name"` - Explicit column name

## Generated Methods
1. **`Insert(ctx, db)`** - Insert single row
2. **`Update(ctx, db)`** - Update by ID fields
3. **`Delete(ctx, db, idValues...)`** - Delete by ID fields
4. **`Get(ctx, db, idValues...)`** - Get by ID fields, returns `error`
5. **`List(ctx, db)`** - Returns `iter.Seq2[*T, error]`
6. **`Find(ctx, db, filter, token)`** - Returns `*FindResult` with pagination

## Filter Behavior
- Filter struct has pointer types
- `nil` pointer = field not included in WHERE clause
- Fully nil filter = same SQL as `List*` (no WHERE)

## Pagination
- Limit is hardcoded to 50
- Token is base64-encoded offset
- Empty token = first page, empty NextToken = end of results
- Use OFFSET for pagination

## go:generate Directive
Uses `GOLINE` to find the struct on the next line:
```go
//go:generate pg_generator -table=table_name -gol=$GOLINE
```

## Output File
Generated file is `<StructName>.generated.go` in the same directory as the source.

## Example

Input:
```go
//go:generate pg_generator -table=accounts -gol=$GOLINE
type Account struct {
    ID    string `db:id`
    Name  string `db:filter`
    Email string `db:filter`
}
```

Output (`Account.generated.go`):
```go
type AccountFilter struct {
    Name  *string
    Email *string
}

type AccountFindResult struct {
    Items     []*Account
    NextToken string
}

func (a *Account) Insert(ctx context.Context, db *sql.DB) error { ... }
func (a *Account) Update(ctx context.Context, db *sql.DB) error { ... }
func (a *Account) Delete(ctx context.Context, db *sql.DB, id string) error { ... }
func (a *Account) Get(ctx context.Context, db *sql.DB, id string) error { ... }
func (a *Account) List(ctx context.Context, db *sql.DB) iter.Seq2[*Account, error] { ... }
func (a *Account) Find(ctx context.Context, db *sql.DB, filter AccountFilter, token string) (*AccountFindResult, error) { ... }
```

## Files Created
| File | Action |
|------|--------|
| `cmd/pg_generator/main.go` | New generator |

## Verification
1. `go build ./cmd/pg_generator`
2. Add directive to model file
3. `go generate ./...`
4. `go build ./...`
