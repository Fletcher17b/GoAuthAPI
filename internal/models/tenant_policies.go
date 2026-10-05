package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// nts TODO:do SQL, not implemented

type PolicyState string

const (
	allowed      PolicyState = "allowed"      //nolint:unused
	undetermined PolicyState = "undetermined" //nolint:unused
	disallowed   PolicyState = "disallowed"   //nolint:unused
)

type EmailEvents struct {
	EmailWelcomeMessage PolicyState

	EmailVerificationRequested  PolicyState
	EmailPasswordResetRequested PolicyState
}

type SMSEvents struct {
	TwoStepVerify     PolicyState
	ResetPasswordCode PolicyState
	LoginCode         PolicyState
}

type PushEvents struct {
	NotificationConfirm PolicyState
	// Generefic For Future
}

type UserEvents struct {
	UserCreated                 PolicyState `json:"UserCreated"`
	UserUpdated                 PolicyState `json:"UserUpdated"`
	UserLoginSucceeded          PolicyState `json:"UserLoginSucceeded"`
	UserLoginFailed             PolicyState `json:"UserLoginFailed"`
	UserPasswordResetRequired   PolicyState `json:"UserPasswordResetRequired"`
	UserPasswordResetSucceeded  PolicyState `json:"UserPasswordResetSucceeded"`
	EmailVerificationRequested  PolicyState `json:"EmailVerificationRequested"`
	EmailPasswordResetRequested PolicyState `json:"EmailPasswordResetRequested"`
}

type EmailPolicy struct {
	Enabled    bool        `json:"enabled"`
	Events     EmailEvents `json:"events"`
	UserEvents UserEvents  `json:"userevents"`
}

type SMSPolicy struct {
	Enabled    bool       `json:"enabled"`
	Events     SMSEvents  `json:"events"`
	UserEvents UserEvents `json:"userevents"`
}

type PushPolicy struct {
	Enabled    bool       `json:"enabled"`
	Events     PushEvents `json:"events"`
	UserEvents UserEvents `json:"userevents"`
}

type TenantNotificationPolicies struct {
	Sms_policy   SMSPolicy
	Email_policy EmailPolicy
	Push_policy  PushPolicy
}

type tenant_policies struct { //nolint:unused
	TenantId           uuid.UUID // FK
	ApiKey             uuid.UUID // Semi FK, can be used as an indentifier, probs gonna need an index
	PolicyVersion      string
	NotificationPolicy json.RawMessage // json.Marshal()
	RatePolicies       json.RawMessage
	CustomPolicies     json.RawMessage
	UpdatedAt          *time.Time
	CreatedAt          time.Time `db:"created_at" json:"created_at"`
}

type WarningNotificationMethods struct {
	PreferedMethod   string // has to be one of the methods bellow
	SMS              bool
	Email            bool
	PushNotification bool
}

type ProgressiveDelays struct {
	Enabled bool
	// nts: TODO: Find a way to represent progressive delay decision tree in a struct

}

type LoginRatePolicy struct {
	ProgressiveDelaysConfig ProgressiveDelays
	WarningNotification     WarningNotificationMethods
}

type SignupRatePolicy struct {
	ProgressiveDelaysConfig ProgressiveDelays
	WarningNotification     WarningNotificationMethods
}

type ResetRequestRatePolicy struct {
	ProgressiveDelaysConfig ProgressiveDelays
	WarningNotification     WarningNotificationMethods
}

type RatePolicies struct {
	LoginPolicy            LoginRatePolicy
	SignupRatePolicy       SignupRatePolicy
	ResetRequestRatePolicy ResetRequestRatePolicy
}

/*
Full TenantPolicies Table: TenantID (FK), API-KEY (FK), PolicyVersion ,NotifationPolicies, RatePolicies,CustomPolicies ,CreationDate, UpdatedAt


*/
