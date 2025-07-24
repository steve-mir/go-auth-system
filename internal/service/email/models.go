package email

import (
	"time"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// EmailConfig represents email service configuration
type EmailConfig struct {
	DefaultProvider interfaces.EmailProvider  `yaml:"default_provider"`
	Providers       map[string]ProviderConfig `yaml:"providers"`
	Templates       TemplateConfig            `yaml:"templates"`
	RateLimit       RateLimitConfig           `yaml:"rate_limit"`
	Tracking        TrackingConfig            `yaml:"tracking"`
	Retry           RetryConfig               `yaml:"retry"`
}

// ProviderConfig represents configuration for an email provider
type ProviderConfig struct {
	Type     interfaces.EmailProvider   `yaml:"type"`
	Enabled  bool                       `yaml:"enabled"`
	Priority int                        `yaml:"priority"`
	SMTP     *interfaces.SMTPConfig     `yaml:"smtp,omitempty"`
	SendGrid *interfaces.SendGridConfig `yaml:"sendgrid,omitempty"`
	Mailgun  *interfaces.MailgunConfig  `yaml:"mailgun,omitempty"`
	SES      *interfaces.SESConfig      `yaml:"ses,omitempty"`
	Postmark *interfaces.PostmarkConfig `yaml:"postmark,omitempty"`
	Resend   *interfaces.ResendConfig   `yaml:"resend,omitempty"`
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
