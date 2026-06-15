package mail

type Mailer interface {
	SendVerificationEmail(to string, token string) error
}
