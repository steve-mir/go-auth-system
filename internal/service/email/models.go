package email

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

// EmailConfig represents email service configuration
type EmailConfig struct {
	DefaultProvider EmailProvider             `yaml:"default_provider"`
	Providers       map[string]ProviderConfig `yaml:"providers"`
	Templates       TemplateConfig            `yaml:"templates"`
	RateLimit       RateLimitConfig           `yaml:"rate_limit"`
	Tracking        TrackingConfig            `yaml:"tracking"`
	Retry           RetryConfig               `yaml:"retry"`
}

// ProviderConfig represents configuration for an email provider
type ProviderConfig struct {
	Type     EmailProvider   `yaml:"type"`
	Enabled  bool            `yaml:"enabled"`
	Priority int             `yaml:"priority"`
	SMTP     *SMTPConfig     `yaml:"smtp,omitempty"`
	SendGrid *SendGridConfig `yaml:"sendgrid,omitempty"`
	Mailgun  *MailgunConfig  `yaml:"mailgun,omitempty"`
	SES      *SESConfig      `yaml:"ses,omitempty"`
	Postmark *PostmarkConfig `yaml:"postmark,omitempty"`
	Resend   *ResendConfig   `yaml:"resend,omitempty"`
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

// SendGridConfig represents SendGrid configuration
type SendGridConfig struct {
	APIKey string `yaml:"api_key"`
}

// MailgunConfig represents Mailgun configuration
type MailgunConfig struct {
	APIKey string `yaml:"api_key"`
	Domain string `yaml:"domain"`
	Region string `yaml:"region"`
}

// SESConfig represents AWS SES configuration
type SESConfig struct {
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	SessionToken    string `yaml:"session_token,omitempty"`
}

// PostmarkConfig represents Postmark configuration
type PostmarkConfig struct {
	APIKey string `yaml:"api_key"`
}

// ResendConfig represents Resend configuration
type ResendConfig struct {
	APIKey string `yaml:"api_key"`
}

// TemplateConfig represents template configuration
type TemplateConfig struct {
	DefaultFrom     string `yaml:"default_from"`
	DefaultFromName string `yaml:"default_from_name"`
	BaseURL         string `yaml:"base_url"`
	AssetsURL       string `yaml:"assets_url"`
	UnsubscribeURL  string `yaml:"unsubscribe_url"`
}

// RateLimitConfig represents rate limiting configuration
type RateLimitConfig struct {
	Enabled        bool          `yaml:"enabled"`
	RequestsPerMin int           `yaml:"requests_per_minute"`
	BurstSize      int           `yaml:"burst_size"`
	WindowSize     time.Duration `yaml:"window_size"`
}

// TrackingConfig represents email tracking configuration
type TrackingConfig struct {
	Enabled        bool   `yaml:"enabled"`
	OpenTracking   bool   `yaml:"open_tracking"`
	ClickTracking  bool   `yaml:"click_tracking"`
	TrackingDomain string `yaml:"tracking_domain"`
}

// RetryConfig represents retry configuration
type RetryConfig struct {
	Enabled      bool          `yaml:"enabled"`
	MaxRetries   int           `yaml:"max_retries"`
	InitialDelay time.Duration `yaml:"initial_delay"`
	MaxDelay     time.Duration `yaml:"max_delay"`
	Multiplier   float64       `yaml:"multiplier"`
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

// PrebuiltTemplates contains IDs for prebuilt email templates
type PrebuiltTemplates struct {
	Welcome           string
	Verification      string
	PasswordReset     string
	LoginNotification string
	MFACode           string
	AccountLocked     string
	PasswordChanged   string
}

// DefaultPrebuiltTemplates returns the default prebuilt template IDs
func DefaultPrebuiltTemplates() *PrebuiltTemplates {
	return &PrebuiltTemplates{
		Welcome:           "welcome",
		Verification:      "email-verification",
		PasswordReset:     "password-reset",
		LoginNotification: "login-notification",
		MFACode:           "mfa-code",
		AccountLocked:     "account-locked",
		PasswordChanged:   "password-changed",
	}
}
