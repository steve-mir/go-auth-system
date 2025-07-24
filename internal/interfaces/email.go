package interfaces

import (
	"errors"
	"time"
)

// Common email errors
var (
	ErrInvalidEmailAddress = errors.New("invalid email address")
	ErrTemplateNotFound    = errors.New("email template not found")
	ErrProviderNotFound    = errors.New("email provider not found")
	ErrSendFailed          = errors.New("failed to send email")
	ErrRateLimitExceeded   = errors.New("rate limit exceeded")
	ErrInvalidTemplate     = errors.New("invalid email template")
	ErrMissingVariables    = errors.New("missing required template variables")
)

// EmailProvider represents different email providers
type EmailProvider string

const (
	ProviderSMTP     EmailProvider = "smtp"
	ProviderSendGrid EmailProvider = "sendgrid"
	ProviderMailgun  EmailProvider = "mailgun"
	ProviderSES      EmailProvider = "ses"
	ProviderPostmark EmailProvider = "postmark"
	ProviderResend   EmailProvider = "resend"
)

// PostmarkConfig represents Postmark configuration
type PostmarkConfig struct {
	APIKey string `yaml:"api_key"`
}

// MailgunConfig represents Mailgun configuration
type MailgunConfig struct {
	APIKey string `yaml:"api_key"`
	Domain string `yaml:"domain"`
	Region string `yaml:"region"`
}

// ResendConfig represents Resend configuration
type ResendConfig struct {
	APIKey string `yaml:"api_key"`
}

// SendGridConfig represents SendGrid configuration
type SendGridConfig struct {
	APIKey string `yaml:"api_key"`
}

// SESConfig represents AWS SES configuration
type SESConfig struct {
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token,omitempty"`
}

// SMTPConfig represents SMTP configuration
type SMTPConfig struct {
	Host       string `yaml:"host"`
	Port       int    `yaml:"port"`
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	TLS        bool   `yaml:"tls"`
	StartTLS   bool   `yaml:"start_tls"`
	SkipVerify bool   `yaml:"skip_verify"`
}

// EmailQueue represents an email in the queue
type EmailQueue struct {
	ID          string            `json:"id"`
	Request     *SendEmailRequest `json:"request"`
	Status      DeliveryStatus    `json:"status"`
	Provider    EmailProvider     `json:"provider"`
	Attempts    int               `json:"attempts"`
	MaxAttempts int               `json:"max_attempts"`
	NextRetry   *time.Time        `json:"next_retry,omitempty"`
	Error       string            `json:"error,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// EmailLog represents an email log entry
type EmailLog struct {
	ID        string            `json:"id"`
	EmailID   string            `json:"email_id"`
	Event     string            `json:"event"`
	Timestamp time.Time         `json:"timestamp"`
	Data      map[string]string `json:"data,omitempty"`
	UserAgent string            `json:"user_agent,omitempty"`
	IPAddress string            `json:"ip_address,omitempty"`
}
