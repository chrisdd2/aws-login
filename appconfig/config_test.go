package appconfig

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppConfig_LoadDefaults(t *testing.T) {
	t.Run("sets default values", func(t *testing.T) {
		cfg := &AppConfig{}
		err := cfg.LoadDefaults()
		require.NoError(t, err)

		assert.Equal(t, "development", cfg.Environment)
		assert.Equal(t, "localhost:8099", cfg.MetrisAddr)
		assert.Equal(t, "localhost:8090", cfg.ListenAddr)
		assert.Equal(t, false, cfg.DevelopmentMode)
		assert.Equal(t, "file", cfg.Storage.Type)
		assert.Equal(t, ".config", cfg.Storage.Directory)
	})

	t.Run("nested struct defaults", func(t *testing.T) {
		cfg := &AppConfig{}
		err := cfg.LoadDefaults()
		require.NoError(t, err)

		assert.Equal(t, 5432, cfg.Storage.Postgres.Port)
	})
}

func TestAppConfig_LoadFromEnv(t *testing.T) {
	t.Run("overrides with environment variables", func(t *testing.T) {
		cfg := &AppConfig{}
		cfg.SetEnvironmentVariablePrefix("AWS_LOGIN")

		t.Setenv("AWS_LOGIN__ENVIRONMENT", "production")
		t.Setenv("AWS_LOGIN__LISTEN_ADDR", "0.0.0.0:8080")
		t.Setenv("AWS_LOGIN__STORAGE__POSTGRES__HOST", "db.example.com")
		t.Setenv("AWS_LOGIN__STORAGE__POSTGRES__PORT", "5433")

		err := cfg.LoadFromEnv()
		require.NoError(t, err)

		assert.Equal(t, "production", cfg.Environment)
		assert.Equal(t, "0.0.0.0:8080", cfg.ListenAddr)
		assert.Equal(t, "db.example.com", cfg.Storage.Postgres.Host)
		assert.Equal(t, 5433, cfg.Storage.Postgres.Port)
	})

	t.Run("boolean environment override", func(t *testing.T) {
		cfg := &AppConfig{}
		cfg.SetEnvironmentVariablePrefix("")

		t.Setenv("__DEVELOPMENT_MODE", "true")
		err := cfg.LoadFromEnv()
		require.NoError(t, err)
		assert.True(t, cfg.DevelopmentMode)
	})

	t.Run("array/slice environment override", func(t *testing.T) {
		cfg := &AppConfig{}
		cfg.SetEnvironmentVariablePrefix("")

		t.Setenv("__AUTH__GOOGLE_WORKSPACES", "domain1.com,domain2.com,domain3.com")
		err := cfg.LoadFromEnv()
		require.NoError(t, err)

		assert.Equal(t, []string{"domain1.com", "domain2.com", "domain3.com"}, cfg.Auth.GoogleWorkspaces)
	})
}

func TestAppConfig_LoadFromYaml(t *testing.T) {
	yamlContent := `
name: test-app
environment: production
listen_addr: 0.0.0.0:9000
storage:
  type: postgres
  postgres:
    host: yaml-db.example.com
    port: 5432
    database: appdb
    username: appuser
    password: secret
auth:
  sign_key: test-signing-key
`
	t.Run("parses YAML configuration", func(t *testing.T) {
		cfg := &AppConfig{}
		err := cfg.LoadFromYaml(strings.NewReader(yamlContent))
		require.NoError(t, err)

		assert.Equal(t, "test-app", cfg.Name)
		assert.Equal(t, "production", cfg.Environment)
		assert.Equal(t, "0.0.0.0:9000", cfg.ListenAddr)
		assert.Equal(t, "postgres", cfg.Storage.Type)
		assert.Equal(t, "yaml-db.example.com", cfg.Storage.Postgres.Host)
		assert.Equal(t, "appdb", cfg.Storage.Postgres.Database)
		assert.Equal(t, "appuser", cfg.Storage.Postgres.Username)
	})

	t.Run("handles empty YAML", func(t *testing.T) {
		cfg := &AppConfig{}
		err := cfg.LoadFromYaml(strings.NewReader(""))
		require.NoError(t, err)
	})
}

func TestAppConfig_IsProduction(t *testing.T) {
	tests := []struct {
		env      string
		expected bool
	}{
		{"production", true},
		{"Production", false}, // case-sensitive
		{"production ", false},
		{"", false},
		{"development", false},
		{"staging", false},
	}

	for _, tt := range tests {
		t.Run(tt.env, func(t *testing.T) {
			cfg := &AppConfig{Environment: tt.env}
			assert.Equal(t, tt.expected, cfg.IsProduction())
		})
	}
}

func TestAppConfig_PrefixEnv(t *testing.T) {
	cfg := &AppConfig{}
	cfg.SetEnvironmentVariablePrefix("MYAPP_")

	result := cfg.PrefixEnv("TEST_VAR")
	assert.Equal(t, "MYAPP_TEST_VAR", result)
}

func TestEnvWalk_InvalidTypes(t *testing.T) {
	t.Run("invalid int value", func(t *testing.T) {
		cfg := &AppConfig{}
		cfg.SetEnvironmentVariablePrefix("")

		t.Setenv("__STORAGE__POSTGRES__PORT", "not-a-number")
		err := cfg.LoadFromEnv()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid value")
	})

	t.Run("invalid bool value", func(t *testing.T) {
		cfg := &AppConfig{}
		cfg.SetEnvironmentVariablePrefix("")

		// Invalid bools are treated as true, so no error expected
		t.Setenv("__DEVELOPMENT_MODE", "maybe")
		err := cfg.LoadFromEnv()
		require.NoError(t, err)
		assert.True(t, cfg.DevelopmentMode)
	})
}

func TestMaskValue(t *testing.T) {
	tests := []struct {
		value    string
		mask     bool
		expected string
	}{
		{"secret123", true, "*********"},
		{"secret123", false, "secret123"},
		{"", true, ""},
		{"", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			var tag reflect.StructTag
			if tt.mask {
				tag = `mask:"true"`
			}
			result := maskValue(tt.value, tag)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPrettyPath(t *testing.T) {
	tests := []struct {
		key      string
		path     []string
		expected string
	}{
		{"port", []string{"storage", "postgres"}, "storage.postgres.port"},
		{"host", []string{}, "host"},
		{"value", []string{"a", "b", "c"}, "a.b.c.value"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := prettyPath(tt.key, tt.path...)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPatchEnvironment(t *testing.T) {
	t.Run("restores existing env vars", func(t *testing.T) {
		os.Setenv("TEST_PATCH_VAR", "before")
		original := os.Getenv("TEST_PATCH_VAR")
		restore := patchEnvironment(map[string]string{"TEST_PATCH_VAR": "after"})

		assert.Equal(t, "after", os.Getenv("TEST_PATCH_VAR"))

		restore()

		assert.Equal(t, original, os.Getenv("TEST_PATCH_VAR"))
	})

	t.Run("unsets new env vars", func(t *testing.T) {
		os.Unsetenv("TEST_NEW_VAR")
		restore := patchEnvironment(map[string]string{"TEST_NEW_VAR": "value"})

		assert.Equal(t, "value", os.Getenv("TEST_NEW_VAR"))

		restore()

		_, exists := os.LookupEnv("TEST_NEW_VAR")
		assert.False(t, exists)
	})
}
