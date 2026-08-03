package config

import "AuthAPI/main/internal/auth/mail"

type Config struct {
	AppBaseURL           string
	SMTP                 mail.SMTPMailer
	CORS_ALLOWED_ORIGINS []string

	Database    DatabaseConfig
	Broker      BrokerConfig
	Environment string
	LogLevel    string
}

type SQLiteConfig struct {
	Path string
}

type PostgresConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	Database string
	/* SSLMode  string */
}

type DatabaseConfig struct {
	Driver       string
	SqliteConf   SQLiteConfig
	PostgresConf PostgresConfig
}

type BrokerConfig struct {
	URL      string
	Exchange string
}
