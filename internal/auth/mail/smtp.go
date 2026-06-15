package mail

import (
	"fmt"
	"net/smtp"
)

type SMTPMailer struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	BaseURL  string
}

func (m *SMTPMailer) SendVerificationEmail(to string, token string) error {
	auth := smtp.PlainAuth(
		"",
		m.Username,
		m.Password,
		m.Host,
	)

	link := fmt.Sprintf(
		"%s/verify-email?t=%s",
		m.BaseURL,
		token,
	)

	msg := []byte(
		"From: " + m.From + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: Verify your email\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/html; charset=UTF-8\r\n" +
			"\r\n" +
			`<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<style>
		body { font-family: Arial, sans-serif; line-height: 1.6; color: #333333; }
		.container { max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px; }
		.header { font-size: 24px; font-weight: bold; color: #1a73e8; margin-bottom: 20px; }
		.button { display: inline-block; padding: 12px 24px; margin: 20px 0; color: #ffffff !important; background-color: #1a73e8; text-decoration: none; border-radius: 4px; font-weight: bold; }
		.footer { margin-top: 30px; font-size: 12px; color: #666666; border-top: 1px solid #eeeeee; padding-top: 10px; }
	</style>
</head>
<body>
	<div class="container">
		<div class="header">Welcome aboard!</div>
		<p>Hi there,</p>
		<p>Thank you for signing up. Please click the button below to verify your email address and activate your account:</p>

		<a href="` + link + `" class="button">Verify Email Address</a>

		<p>If the button doesn't work, copy and paste this link:</p>
		<p style="font-size: 12px; word-break: break-all;">
			<a href="` + link + `">` + link + `</a>
		</p>

		<div class="footer">
			<p>If you didn't create an account, you can safely ignore this email.</p>
			<p>&copy; Your Company Name</p>
		</div>
	</div>
</body>
</html>`,
	)
	addr := fmt.Sprintf("%s:%d", m.Host, m.Port)

	return smtp.SendMail(
		addr,
		auth,
		m.Username,
		[]string{to},
		msg,
	)
}
