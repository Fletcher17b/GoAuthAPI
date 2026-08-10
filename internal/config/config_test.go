package config

import (
	"fmt"
	"reflect"
	"testing"
)

// ---------- getEnv ----------

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   string // "" means: do not set the var at all
		setVar  bool
		wantErr bool
	}{
		{"present and non-empty", "TEST_GETENV_KEY", "hello", true, false},
		{"present but empty string", "TEST_GETENV_KEY", "", true, true}, // os.Getenv("")=="" is treated as unset
		{"not set at all", "TEST_GETENV_KEY", "", false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setVar {
				t.Setenv(tt.key, tt.value)
			}

			got, err := getEnv(tt.key)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (value=%q)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.value {
				t.Fatalf("got %q, want %q", got, tt.value)
			}
		})
	}
}

// ---------- parseEnvList ----------

func TestParseEnvList(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty string", "", nil},
		{"single value", "http://localhost:3000", []string{"http://localhost:3000"}},
		{
			"multiple comma separated",
			"http://a.com,http://b.com,http://c.com",
			[]string{"http://a.com", "http://b.com", "http://c.com"},
		},
		{
			"trims surrounding whitespace",
			" http://a.com , http://b.com ",
			[]string{"http://a.com", "http://b.com"},
		},
		{
			"trims surrounding double quotes",
			`"http://a.com","http://b.com"`,
			[]string{"http://a.com", "http://b.com"},
		},
		{
			"drops empty entries from trailing/double commas",
			"http://a.com,,http://b.com,",
			[]string{"http://a.com", "http://b.com"},
		},
		{
			"all whitespace/empty entries collapse to nil",
			" , , ",
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEnvList(tt.raw)
			fmt.Print(tt.name)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseEnvList(%q) = %#v, want %#v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestLoadBrokerConfig(t *testing.T) {
	t.Run("defaults when unset", func(t *testing.T) {
		t.Setenv("RABBITMQ_URL", "")
		t.Setenv("RABBITMQ_EXCHANGE", "")

		got := LoadBrokerConfig()

		want := BrokerConfig{
			URL:      "amqp://guest:guest@localhost:5672/",
			Exchange: "authapi.events",
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("uses configured values", func(t *testing.T) {
		t.Setenv("RABBITMQ_URL", "amqp://user:pass@broker:5672/")
		t.Setenv("RABBITMQ_EXCHANGE", "custom.exchange")

		got := LoadBrokerConfig()

		want := BrokerConfig{
			URL:      "amqp://user:pass@broker:5672/",
			Exchange: "custom.exchange",
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("partial override keeps other default", func(t *testing.T) {
		t.Setenv("RABBITMQ_URL", "amqp://only-url-set/")
		t.Setenv("RABBITMQ_EXCHANGE", "")

		got := LoadBrokerConfig()

		if got.URL != "amqp://only-url-set/" {
			t.Errorf("URL = %q, want %q", got.URL, "amqp://only-url-set/")
		}
		if got.Exchange != "authapi.events" {
			t.Errorf("Exchange = %q, want default %q", got.Exchange, "authapi.events")
		}
	})
}

func TestSetupSQLiteConfig(t *testing.T) {
	t.Run("uses configured path", func(t *testing.T) {
		t.Setenv("SQLITE_PATH", "/data/custom.db")
		got := setupSQLiteConfig()
		if got.Path != "/data/custom.db" {
			t.Fatalf("Path = %q, want %q", got.Path, "/data/custom.db")
		}
	})

	t.Run("defaults when unset", func(t *testing.T) {
		t.Setenv("SQLITE_PATH", "")
		got := setupSQLiteConfig()
		if got.Path != "auth.db" {
			t.Fatalf("Path = %q, want default %q", got.Path, "auth.db")
		}
	})
}

func TestPostgresConfLoader(t *testing.T) {
	setAllValid := func(t *testing.T) {
		t.Setenv("PSQL_HOST", "db.internal")
		t.Setenv("PSQL_PORT", "5432")
		t.Setenv("PSQL_USER", "authapi")
		t.Setenv("PSQL_PASSWORD", "s3cret")
		t.Setenv("PSQL_DATABASE", "authapi_db")
	}

	t.Run("all fields present and valid", func(t *testing.T) {
		setAllValid(t)

		got, err := PostgresConfLoader()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := PostgresConfig{
			Host:     "db.internal",
			Port:     5432,
			User:     "authapi",
			Password: "s3cret",
			Database: "authapi_db",
		}
		if got != want {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("missing host", func(t *testing.T) {
		setAllValid(t)
		t.Setenv("PSQL_HOST", "")

		_, err := PostgresConfLoader()
		if err == nil {
			t.Fatal("expected error when PSQL_HOST is missing")
		}
	})

	t.Run("missing port", func(t *testing.T) {
		setAllValid(t)
		t.Setenv("PSQL_PORT", "")

		_, err := PostgresConfLoader()
		if err == nil {
			t.Fatal("expected error when PSQL_PORT is missing")
		}
	})

	t.Run("non-numeric port", func(t *testing.T) {
		setAllValid(t)
		t.Setenv("PSQL_PORT", "not-a-number")

		_, err := PostgresConfLoader()
		if err == nil {
			t.Fatal("expected error when PSQL_PORT is not numeric")
		}
	})

	t.Run("missing user", func(t *testing.T) {
		setAllValid(t)
		t.Setenv("PSQL_USER", "")

		_, err := PostgresConfLoader()
		if err == nil {
			t.Fatal("expected error when PSQL_USER is missing")
		}
	})

	t.Run("missing password", func(t *testing.T) {
		setAllValid(t)
		t.Setenv("PSQL_PASSWORD", "")

		_, err := PostgresConfLoader()
		if err == nil {
			t.Fatal("expected error when PSQL_PASSWORD is missing")
		}
	})

	t.Run("missing database name", func(t *testing.T) {
		setAllValid(t)
		t.Setenv("PSQL_DATABASE", "")

		_, err := PostgresConfLoader()
		if err == nil {
			t.Fatal("expected error when PSQL_DATABASE is missing")
		}
	})

	t.Run("all missing returns empty config and error", func(t *testing.T) {
		t.Setenv("PSQL_HOST", "")
		t.Setenv("PSQL_PORT", "")
		t.Setenv("PSQL_USER", "")
		t.Setenv("PSQL_PASSWORD", "")
		t.Setenv("PSQL_DATABASE", "")

		got, err := PostgresConfLoader()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if got != (PostgresConfig{}) {
			t.Fatalf("expected zero-value config on failure, got %+v", got)
		}
	})
}

func TestLoadDBconfigs(t *testing.T) {
	t.Run("defaults to sqlite when DB_DRIVER unset", func(t *testing.T) {
		t.Setenv("DB_DRIVER", "")
		t.Setenv("SQLITE_PATH", "")

		got, err := LoadDBconfigs()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Driver != "sqlite" {
			t.Errorf("Driver = %q, want %q", got.Driver, "sqlite")
		}
		if got.SqliteConf.Path != "auth.db" {
			t.Errorf("SqliteConf.Path = %q, want default %q", got.SqliteConf.Path, "auth.db")
		}
	})

	t.Run("explicit sqlite driver with custom path", func(t *testing.T) {
		t.Setenv("DB_DRIVER", "sqlite")
		t.Setenv("SQLITE_PATH", "/tmp/custom.db")

		got, err := LoadDBconfigs()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Driver != "sqlite" {
			t.Errorf("Driver = %q, want %q", got.Driver, "sqlite")
		}
		if got.SqliteConf.Path != "/tmp/custom.db" {
			t.Errorf("SqliteConf.Path = %q, want %q", got.SqliteConf.Path, "/tmp/custom.db")
		}
	})

	t.Run("postgres driver with valid postgres env falls through to postgres config", func(t *testing.T) {
		t.Setenv("DB_DRIVER", "postgres")
		t.Setenv("PSQL_HOST", "db.internal")
		t.Setenv("PSQL_PORT", "5432")
		t.Setenv("PSQL_USER", "authapi")
		t.Setenv("PSQL_PASSWORD", "s3cret")
		t.Setenv("PSQL_DATABASE", "authapi_db")

		got, err := LoadDBconfigs()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Driver != "postgres" {
			t.Errorf("Driver = %q, want %q", got.Driver, "postgres")
		}
		if got.PostgresConf.Host != "db.internal" {
			t.Errorf("PostgresConf.Host = %q, want %q", got.PostgresConf.Host, "db.internal")
		}
	})

	t.Run("postgres driver with invalid postgres env falls back to sqlite", func(t *testing.T) {
		t.Setenv("DB_DRIVER", "postgres")
		t.Setenv("PSQL_HOST", "")
		t.Setenv("PSQL_PORT", "")
		t.Setenv("PSQL_USER", "")
		t.Setenv("PSQL_PASSWORD", "")
		t.Setenv("PSQL_DATABASE", "")
		t.Setenv("SQLITE_PATH", "")

		got, err := LoadDBconfigs()
		if err != nil {
			t.Fatalf("unexpected error: %v (should fall back, not error)", err)
		}
		if got.Driver != "sqlite" {
			t.Errorf("Driver = %q, want fallback %q", got.Driver, "sqlite")
		}
		if got.SqliteConf.Path != "auth.db" {
			t.Errorf("SqliteConf.Path = %q, want default %q", got.SqliteConf.Path, "auth.db")
		}
	})

	t.Run("unknown driver returns error", func(t *testing.T) {
		t.Setenv("DB_DRIVER", "mongodb")

		_, err := LoadDBconfigs()
		if err == nil {
			t.Fatal("expected error for unknown driver, got nil")
		}
	})
}

func TestLoadMailerConfig(t *testing.T) {
	setAllValid := func(t *testing.T) {
		t.Setenv("SMTP_HOST", "smtp.example.com")
		t.Setenv("SMTP_USER", "noreply@example.com")
		t.Setenv("SMTP_APP_PASSWORD", "app-password")
		t.Setenv("SMTP_FROM", "AuthAPI <noreply@example.com>")
	}

	t.Run("all fields present", func(t *testing.T) {
		setAllValid(t)

		got, err := LoadMailerConfig(587, "https://app.example.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil {
			t.Fatal("expected non-nil mailer config")
		}
		if got.Host != "smtp.example.com" {
			t.Errorf("Host = %q, want %q", got.Host, "smtp.example.com")
		}
		if got.Port != 587 {
			t.Errorf("Port = %d, want %d", got.Port, 587)
		}
		if got.Username != "noreply@example.com" {
			t.Errorf("Username = %q, want %q", got.Username, "noreply@example.com")
		}
		if got.Password != "app-password" {
			t.Errorf("Password = %q, want %q", got.Password, "app-password")
		}
		if got.From != "AuthAPI <noreply@example.com>" {
			t.Errorf("From = %q, want %q", got.From, "AuthAPI <noreply@example.com>")
		}
		if got.BaseURL != "https://app.example.com" {
			t.Errorf("BaseURL = %q, want %q", got.BaseURL, "https://app.example.com")
		}
	})

	missingCases := []string{"SMTP_HOST", "SMTP_USER", "SMTP_APP_PASSWORD", "SMTP_FROM"}
	for _, missing := range missingCases {
		missing := missing
		t.Run("missing "+missing, func(t *testing.T) {
			setAllValid(t)
			t.Setenv(missing, "")

			got, err := LoadMailerConfig(587, "https://app.example.com")
			if err == nil {
				t.Fatalf("expected error when %s is missing", missing)
			}
			if got != nil {
				t.Fatalf("expected nil mailer config on error, got %+v", got)
			}
		})
	}
}

func TestLoadCors(t *testing.T) {
	t.Run("returns non-nil handler with configured origins", func(t *testing.T) {
		cfg := Config{CORS_ALLOWED_ORIGINS: []string{"https://app.example.com", " https://admin.example.com "}}
		c := LoadCors(cfg)
		if c == nil {
			t.Fatal("expected non-nil cors handler")
		}
	})

	t.Run("returns non-nil handler with no origins configured", func(t *testing.T) {
		cfg := Config{CORS_ALLOWED_ORIGINS: nil}
		c := LoadCors(cfg)
		if c == nil {
			t.Fatal("expected non-nil cors handler even with wildcard fallback")
		}
	})

	t.Run("origins with only whitespace treated as empty", func(t *testing.T) {
		cfg := Config{CORS_ALLOWED_ORIGINS: []string{"   ", ""}}
		c := LoadCors(cfg)
		if c == nil {
			t.Fatal("expected non-nil cors handler")
		}
	})
}
