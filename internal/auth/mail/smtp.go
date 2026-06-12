package mail

import (
	"fmt"
	"net/smtp"
)

type SMTPMailer struct {
	host string
	port string
	user string
	pass string
	from string
}

func NewSMTPMailer(host, port, user, pass, from string) *SMTPMailer {
	return &SMTPMailer{host, port, user, pass, from}
}

func (m *SMTPMailer) Send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%s", m.host, m.port)

	msg := []byte(
		"From: " + m.from + "\r\n" +
			"To: " + to + "\r\n" +
			"Subject: " + subject + "\r\n" +
			"MIME-Version: 1.0\r\n" +
			"Content-Type: text/plain; charset=\"UTF-8\"\r\n\r\n" +
			body,
	)

	auth := smtp.PlainAuth("", m.user, m.pass, m.host)
	return smtp.SendMail(addr, auth, m.user, []string{to}, msg)
}
