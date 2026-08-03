package outbox

type EventType string

const (
	UserCreated EventType = "user.created"

	EmailVerificationRequested EventType = "email.verification.requested"

	PasswordResetRequested EventType = "password.reset.requested"
)
