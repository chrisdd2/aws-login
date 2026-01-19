package appconfig

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"reflect"
	"strconv"
	"strings"

	"sigs.k8s.io/yaml"
)

type OpenIdConfig struct {
	ProviderUrl  string `json:"provider_url,omitempty"`
	RedirectUrl  string `json:"redirect_url,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty" mask:"true"`
}

func (o OpenIdConfig) Enabled() bool {
	return o.ProviderUrl != "" && o.RedirectUrl != "" && o.ClientId != "" && o.ClientSecret != ""
}

type GithubIdpConfig struct {
	ClientSecret string `mask:"true" json:"client_secret,omitempty"`
	ClientId     string `json:"client_id,omitempty"`
	RedirectUrl  string `json:"redirect_url,omitempty"`
}

func (o GithubIdpConfig) Enabled() bool {
	return o.ClientId != "" && o.ClientSecret != ""
}

const (
	StorageTypeFile     = "file"
	StorageTypePostgres = "postgres"
)

type AppConfig struct {
	environmentVariablePrefix string
	Name                      string `json:"name,omitempty" mask:"true"`
	Environment               string `json:"environment,omitempty" default:"development"`
	MetrisAddr                string `json:"metrics_addr,omitempty" default:"localhost:8099"`
	ListenAddr                string `json:"listen_addr,omitempty" default:"localhost:8090"`
	DevelopmentMode           bool   `json:"development_mode,omitempty" default:"false"`
	RootUrl                   string `json:"root_url,omitempty"`
	ConfigFile                string `json:"config_file" default:"app.conf.yml"`
	Storage                   struct {
		Type      string `json:"type" default:"file"`
		Directory string `json:"dir,omitempty" default:".config" `
		Postgres  struct {
			Host     string `json:"host,omitempty"`
			Port     int    `json:"port,omitempty" default:"5432"`
			Database string `json:"database,omitempty"`
			Username string `json:"username,omitempty"`
			Password string `json:"password,omitempty"`
		} `json:"postgres"`
		Sync struct {
			Keycloak struct {
				BaseUrl       string `json:"base_url,omitempty"`
				Realm         string `json:"realm,omitempty"`
				Username      string `json:"username,omitempty"`
				Password      string `json:"password,omitempty"`
				SuperUserRole string `json:"superuser_role,omitempty"`
			} `json:"keycloak"`
		} `json:"sync,omitempty"`
	} `json:"storage,omitempty"`

	Auth struct {
		AdminUsername    string          `json:"admin_username,omitempty"`
		AdminPassword    string          `json:"admin_password,omitempty" mask:"true"`
		SignKey          string          `mask:"true" json:"sign_key,omitempty"`
		Keycloak         OpenIdConfig    `json:"keycloak"`
		Google           OpenIdConfig    `json:"google"`
		Github           GithubIdpConfig `json:"github"`
		GoogleWorkspaces []string        `json:"google_workspaces"`
	} `json:"auth"`
}

func (a *AppConfig) IsProduction() bool {
	return a.Environment == "production"
}

func (a *AppConfig) LoadDefaults() error {
	return defaultsWalk([]string{a.environmentVariablePrefix}, reflect.ValueOf(a))
}

func (a *AppConfig) DebugPrint() {
	debugWalk(0, reflect.ValueOf(a), nil)
}

func (a *AppConfig) LoadFromEnv() error {
	return envWalk([]string{a.environmentVariablePrefix}, reflect.ValueOf(a))
}

func (a *AppConfig) LoadFromYaml(r io.Reader) error {
	bytes, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(bytes, a)
}

func (a *AppConfig) PrefixEnv(v string) string {
	return fmt.Sprintf("%s%s", a.environmentVariablePrefix, v)
}

func (a *AppConfig) SetEnvironmentVariablePrefix(v string) {
	a.environmentVariablePrefix = v
}

func getEnvironmentVariablesWithPrefix(prefix string) map[string]string {
	res := map[string]string{}
	for _, env := range os.Environ() {
		key, value, _ := strings.Cut(env, "=")
		if after, ok := strings.CutPrefix(key, prefix); ok {
			res[after] = value
		}
	}
	return res
}

func WithEnvContext[T any](prefix string, f func() (T, error)) (T, error) {
	restore := patchEnvironment(getEnvironmentVariablesWithPrefix(prefix))
	defer restore()
	return f()
}

func patchEnvironment(envVars map[string]string) (restoreFunc func()) {
	restore := map[string]string{}
	unset := []string{}
	for k, v := range envVars {
		restoreVal, exists := os.LookupEnv(k)
		if exists {
			restore[k] = restoreVal
		} else {
			unset = append(unset, k)
		}
		os.Setenv(k, v)
	}
	return func() {
		for k, v := range restore {
			os.Setenv(k, v)
		}
		for _, k := range unset {
			os.Unsetenv(k)
		}
	}
}

func getFromEnv(key string, path ...string) string {
	var v string
	if len(path) > 0 {
		v = strings.Join(path, "__")
		v = fmt.Sprintf("%s__%s", v, key)
	} else if len(path) > 0 {
		v = key
	}
	v = strings.ToUpper(v)
	return os.Getenv(v)
}

func prettyPath(key string, path ...string) string {
	return strings.ToLower(strings.Join(append(path, key), "."))
}

func maskValue(value any, tags reflect.StructTag) string {
	valueStr := fmt.Sprint(value)
	if tags.Get("mask") != "" {
		return strings.Repeat("*", len(valueStr))
	}
	return valueStr
}

func envWalk(path []string, v reflect.Value) error {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fld := v.Field(i)
		fldType := t.Field(i)
		k := fld.Kind()
		name := fldType.Name
		if k == reflect.Struct {
			err := envWalk(append(path, name), fld)
			if err != nil {
				return err
			}
			continue
		}
		jsonName := strings.Split(fldType.Tag.Get("json"), ",")[0]
		if jsonName != "" {
			name = jsonName
		}
		value := getFromEnv(name, path...)
		if value == "" {
			continue
		}
		if !fld.CanSet() {
			slog.Debug("config", "skipping", prettyPath(name, path...))
			continue
		}
		slog.Debug("config", "set", prettyPath(name, path...), "value", maskValue(value, fldType.Tag), "source", "env")
		switch k {
		case reflect.Array, reflect.Slice:
			fld.Set(reflect.ValueOf(strings.Split(value, ",")))
		case reflect.String:
			fld.SetString(value)
		case reflect.Bool:
			fld.SetBool(!(strings.ToLower(value) == "false" || value == "0"))
		case reflect.Int, reflect.Int16, reflect.Int64, reflect.Int32:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("[%s] invalid value [%s] for int", prettyPath(name, path...), value)
			}
			fld.SetInt(n)
		case reflect.Float32, reflect.Float64:
			n, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return fmt.Errorf("[%s] invalid value [%s] for float", prettyPath(name, path...), value)
			}
			fld.SetFloat(float64(n))
		case reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("[%s] invalid value [%s] for uint", prettyPath(name, path...), value)
			}
			fld.SetFloat(float64(n))
		default:
			slog.Debug("config", "unknown", name, "type", fld.Kind())
		}
	}
	return nil
}

func defaultsWalk(path []string, v reflect.Value) error {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		fld := v.Field(i)
		fldType := t.Field(i)
		k := fld.Kind()
		name := fldType.Name
		if k == reflect.Struct {
			err := defaultsWalk(append(path, name), fld)
			if err != nil {
				return err
			}
			continue
		}
		jsonName := strings.Split(fldType.Tag.Get("json"), ",")[0]
		if jsonName != "" {
			name = jsonName
		}
		value := fldType.Tag.Get("default")
		if value == "" {
			continue
		}
		if !fld.CanSet() {
			slog.Debug("config", "skipping", prettyPath(name, path...))
			continue
		}
		slog.Debug("config", "set", prettyPath(name, path...), "value", maskValue(value, fldType.Tag), "source", "defaults")
		switch k := fld.Kind(); k {
		case reflect.Array, reflect.Slice:
			fld.Set(reflect.ValueOf(strings.Split(value, ",")))
		case reflect.String:
			fld.SetString(value)
		case reflect.Bool:
			fld.SetBool(!(strings.ToLower(value) == "false" || value == "0"))
		case reflect.Int, reflect.Int16, reflect.Int64, reflect.Int32:
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return fmt.Errorf("[%s] invalid value [%s] for int", prettyPath(name, path...), value)
			}
			fld.SetInt(n)
		case reflect.Float32, reflect.Float64:
			n, err := strconv.ParseFloat(value, 64)
			if err != nil {
				return fmt.Errorf("[%s] invalid value [%s] for float", prettyPath(name, path...), value)
			}
			fld.SetFloat(float64(n))
		case reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("[%s] invalid value [%s] for uint", prettyPath(name, path...), value)
			}
			fld.SetFloat(float64(n))
		default:
			slog.Debug("config", "unknown", name, "type", fld.Kind())
		}
	}
	return nil

}

func debugWalk(indent identer, v reflect.Value, fld *reflect.StructField) {
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	t := v.Type()
	name := t.Name()
	if fld != nil {
		name = fld.Name
	}
	fmt.Printf("%s%s {\n", indent, name)
	for i := 0; i < v.NumField(); i++ {
		fld := v.Field(i)
		fldType := t.Field(i)
		name := fldType.Name
		if !fld.CanSet() {
			continue
		}
		if fld.Kind() == reflect.Struct {
			debugWalk(indent+1, fld, &fldType)
			continue
		}
		fmt.Printf("%s%s: %v\n", indent+1, name, maskValue(fld, fldType.Tag))
	}
	fmt.Printf("%s}\n", indent)
}

type identer int

func (s identer) String() string {
	return strings.Repeat("  ", int(s))
}
