package config

import (
	"AuthAPI/main/internal/auth/mail"
	"crypto/rsa"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/go-chi/cors"
	"github.com/joho/godotenv"
)

type envField struct {
	key    string
	target *string
}

func getEnv(key string) (string, error) {
	value := os.Getenv(key)
	if value == "" {
		return "", fmt.Errorf("Missing environment variable %q", key)
	}
	return value, nil
}

func Load() (*Config, error) {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found")
	}

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		return nil, err
	}

	baseURL, err := getEnv("APP_BASE_URL")

	mailconfig, err := LoadMailerConfig(port, baseURL)
	if mailconfig == nil {
		return nil, errors.ErrUnsupported // nts: todo switch to correct error designation
	}

	return &Config{
		AppBaseURL:           baseURL,
		CORS_ALLOWED_ORIGINS: parseEnvList(os.Getenv("CORS_ALLOWED_ORIGINS")),
		SMTP:                 *mailconfig,
	}, nil
}

func LoadKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	priv, err := LoadPrivateKey("private.pem")
	if err != nil {
		log.Fatalf("failed to load private key: %v", err)
	}

	pub, err := LoadPublicKey("public.pem")
	if err != nil {
		log.Fatalf("failed to load public key: %v", err)
	}

	return priv, pub
}

func LoadCors(cfg Config) *cors.Cors {
	allowedOrigins := make([]string, 0, len(cfg.CORS_ALLOWED_ORIGINS))
	for _, origin := range cfg.CORS_ALLOWED_ORIGINS {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			allowedOrigins = append(allowedOrigins, origin)
		}
	}

	options := cors.Options{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"X-Requested-With",
		},
		AllowCredentials: true,
		MaxAge:           300,
	}

	// If no origins are configured, allow all (without credentials).
	if len(allowedOrigins) == 0 {
		options.AllowedOrigins = []string{"*"}
		options.AllowCredentials = false
	}

	return cors.New(options)
}

func LoadMailerConfig(port int, baseURL string) (*mail.SMTPMailer, error) {

	host := os.Getenv("SMTP_HOST")
	user := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_APP_PASSWORD")
	from := os.Getenv("SMTP_FROM")

	if host == "" || user == "" || pass == "" || from == "" {
		return nil, fmt.Errorf("error in mail config")
	}

	SMTPConf := mail.SMTPMailer{
		Host:     host,
		Port:     port,
		Username: user,
		Password: pass,
		From:     from,
		BaseURL:  baseURL,
	}
	return &SMTPConf, nil
}

func LoadDBconfigs() (DatabaseConfig, error) {
	db_driver, err := getEnv("DB_DRIVER")
	if err != nil {
		log.Printf("no database driver configured in env, defaulting to sqlite")
		db_driver = "sqlite"
	}
	sqlite_path, err := getEnv("SQLITE_PATH")
	if err != nil {
		log.Printf("No Sqlite path configured, defaulting to base dir")
		sqlite_path = "auth.db"
	}

	SqliteConf := &SQLiteConfig{Path: sqlite_path}

	var psql_conf_error = false

	PSQL_HOST, err := getEnv("PSQL_HOST")
	if err != nil {
		log.Printf("No Postgres Host field found in env")
		psql_conf_error = true
	}

	port, err := getEnv("PSQL_PORT")
	PSQL_PORT, err := strconv.Atoi(port)
	if err != nil {
		log.Printf("No Postgres Port field found in env")
		psql_conf_error = true
	}

	PSQL_USER, err := getEnv("PSQL_USER")
	if err != nil {
		log.Printf("No Postgres User field found in env")
		psql_conf_error = true
	}

	PSQL_PASSWORD, err := getEnv("PSQL_PASSWORD")
	if err != nil {
		log.Printf("No Postgres Password field found in env")
		psql_conf_error = true
	}

	PSQL_DATABASE, err := getEnv("PSQL_DATABASE")
	if err != nil {
		log.Printf("No Postgres Database field found in env")
		psql_conf_error = true
	}

	PSQL_SSL, err := getEnv("PSQL_SSL")
	if err != nil {
		log.Printf("No Postgres SSL mode field found in env")
		psql_conf_error = true
	}

	if psql_conf_error {
		log.Printf("Postgres configuration failed, falling back to SQLITE config")
		db_driver = "sqlite"
	}

	PostgresConfig := &PostgresConfig{
		Host:     PSQL_HOST,
		Port:     PSQL_PORT,
		User:     PSQL_USER,
		Password: PSQL_PASSWORD,
		Database: PSQL_DATABASE,
		SSLMode:  PSQL_SSL,
	}

	db_config := &DatabaseConfig{
		Driver:       db_driver,
		SqliteConf:   *SqliteConf,
		PostgresConf: *PostgresConfig,
	}

	return *db_config, nil

	//nts: if any future db config (creds, port etc) goes here
}

func parseEnvList(raw string) []string {
	if raw == "" {
		return nil
	}

	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		value = strings.Trim(value, `"`)
		if value != "" {
			out = append(out, value)
		}
	}

	return out
}
