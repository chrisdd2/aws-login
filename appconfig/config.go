package appconfig

import (
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"gopkg.in/yaml.v2"
)

type AppConfig struct {
	environmentVariablePrefix string
	ListenAddr                string `default:"localhost:8090" json:"listen_addr,omitempty"`
	SignKey                   string `default:"somekey" mask:"true" json:"sign_key,omitempty"`
	DevelopmentMode           bool   `default:"false" json:"development_mode,omitempty"`
	ConfigDirectory           string `default:".config" json:"conf_dir,omitempty"`
	ConfigUrl                 string `json:"conf_url,omitempty"`
	GithubClientSecret        string `mask:"true" json:"github_client_secret,omitempty"`
	GithubClientId            string `json:"github_client_id,omitempty"`
	OpenIdProviderUrl         string `json:"openid_provider_url,omitempty"`
	OpenIdRedirectUrl         string `json:"openid_redirect_url,omitempty"`
	OpenIdClientId            string `json:"openid_client_id,omitempty"`
	OpenIdClientSecret        string `json:"openid_client_secret,omitempty"`
	AdminUsername             string `json:"admin_username,omitempty"`
	AdminPassword             string `json:"admin_password,omitempty"`
}

func (a *AppConfig) LoadDefaults() error {
	t := reflect.TypeOf(a).Elem()
	v := reflect.ValueOf(a).Elem()
	for i := range v.NumField() {
		tFld := t.Field(i)
		if !tFld.IsExported() {
			continue
		}
		fld := v.Field(i)
		def := tFld.Tag.Get("default")
		switch k := fld.Kind(); k {
		case reflect.String:
			fld.SetString(def)
		case reflect.Bool:
			def := strings.ToLower(def)
			fld.SetBool(def != "false" && len(def) > 0)
		default:
			return fmt.Errorf("unhandled kind %s", k.String())
		}
	}
	return nil
}

func (a *AppConfig) DebugPrint() {
	t := reflect.TypeOf(a).Elem()
	v := reflect.ValueOf(a).Elem()
	fmt.Print("AppConfig {\n")
	for i := range v.NumField() {
		tFld := t.Field(i)
		if !tFld.IsExported() {
			continue
		}
		fld := v.Field(i)
		val := fmt.Sprint(fld.Interface())
		if len(tFld.Tag.Get("mask")) > 0 {
			// this is a security risk cause it hints size, but you know looks cooler
			val = strings.Repeat("*", len(val))
		}
		fmt.Printf("\t%s: %s\n", tFld.Name, val)
	}
	fmt.Print("}\n")
}

func (a *AppConfig) LoadFromEnv() error {
	t := reflect.TypeOf(a).Elem()
	v := reflect.ValueOf(a).Elem()
	for i := range v.NumField() {
		tFld := t.Field(i)
		if !tFld.IsExported() {
			continue
		}
		fld := v.Field(i)
		name := tFld.Tag.Get("env")
		if name == "" {
			name = tFld.Tag.Get("cfg")
		}
		if name == "" {
			name = strings.Split(tFld.Tag.Get("json"), ",")[0]
		}
		if name == "" {
			return fmt.Errorf("missing cfg or name tag for field %s", tFld.Name)
		}
		envVarName := strings.ToUpper(a.PrefixEnv(name))
		envVar, exists := os.LookupEnv(envVarName)
		if !exists {
			continue
		}
		switch k := fld.Kind(); k {
		case reflect.String:
			fld.SetString(envVar)
		case reflect.Bool:
			def := strings.ToLower(envVar)
			fld.SetBool(def != "false" && len(def) > 0)
		default:
			return fmt.Errorf("unhandled kind %s", k.String())
		}
	}
	return nil
}

func (a *AppConfig) LoadFromYaml(r io.Reader) error {
	return yaml.NewDecoder(r).Decode(a)
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
		if strings.HasPrefix(key, prefix) {
			res[strings.TrimPrefix(key, prefix)] = value
		}
	}
	return res
}

func WithEnvContext[T any](prefix string, f func() (T, error)) (T, error) {
	restore := environmentContext(getEnvironmentVariablesWithPrefix(prefix))
	defer restore()
	return f()
}

func environmentContext(envVars map[string]string) (restoreFunc func()) {
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
