package config

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

type Config struct {
	AppBaseURL           string
	SMTP                 SMTPConfig
	CORS_ALLOWED_ORIGINS []string
}

func Load() (*Config, error) {
	if err := godotenv.Load(".env"); err != nil {
		log.Println("No .env file found")
	}

	port, err := strconv.Atoi(os.Getenv("SMTP_PORT"))
	if err != nil {
		return nil, err
	}

	return &Config{
		AppBaseURL:           os.Getenv("APP_BASE_URL"),
		CORS_ALLOWED_ORIGINS: strings.Split(os.Getenv("CORS_ALLOWED_ORIGINS"), ","),
		SMTP: SMTPConfig{
			Host:     os.Getenv("SMTP_HOST"),
			Port:     port,
			Username: os.Getenv("SMTP_USER"),
			Password: os.Getenv("SMTP_APP_PASSWORD"),
			From:     os.Getenv("SMTP_FROM"),
		},
	}, nil
}
