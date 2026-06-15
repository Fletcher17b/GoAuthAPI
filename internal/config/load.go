package config

import (
	"log"
	"os"
	"strconv"

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
	AppBaseURL string
	SMTP       SMTPConfig
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
		AppBaseURL: os.Getenv("APP_BASE_URL"),
		SMTP: SMTPConfig{
			Host:     os.Getenv("SMTP_HOST"),
			Port:     port,
			Username: os.Getenv("SMTP_USER"),
			Password: os.Getenv("SMTP_APP_PASSWORD"),
			From:     os.Getenv("SMTP_FROM"),
		},
	}, nil
}
