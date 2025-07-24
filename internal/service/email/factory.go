package email

import (
	"github.com/steve-mir/go-auth-system/internal/config"
	"github.com/steve-mir/go-auth-system/internal/interfaces"
	"github.com/steve-mir/go-auth-system/internal/service/email/providers"
)

// NewSMTPProvider creates a new SMTP provider
func NewSMTPProvider(config *interfaces.SMTPConfig) (Provider, error) {
	return providers.NewSMTPProvider(config)
}

// NewSendGridProvider creates a new SendGrid provider
func NewSendGridProvider(config *interfaces.SendGridConfig) (Provider, error) {
	return providers.NewSendGridProvider(config)
}

// NewMailgunProvider creates a new Mailgun provider
func NewMailgunProvider(config *interfaces.MailgunConfig) (Provider, error) {
	return providers.NewMailgunProvider(config)
}

// NewSESProvider creates a new AWS SES provider
func NewSESProvider(config *interfaces.SESConfig) (Provider, error) {
	return providers.NewSESProvider(config)
}

// NewPostmarkProvider creates a new Postmark provider
func NewPostmarkProvider(config *interfaces.PostmarkConfig) (Provider, error) {
	return providers.NewPostmarkProvider(config)
}

// NewResendProvider creates a new Resend provider
func NewResendProvider(config *interfaces.ResendConfig) (Provider, error) {
	return providers.NewResendProvider(config)
}

// ConvertConfigToEmailConfig converts the main config to email service config
func ConvertConfigToEmailConfig(cfg *config.EmailServiceConfig) *EmailConfig {
	emailConfig := &EmailConfig{
		DefaultProvider: interfaces.EmailProvider(cfg.DefaultProvider),
		Providers:       make(map[string]ProviderConfig),
		Templates: TemplateConfig{
			DefaultFrom:     cfg.Templates.DefaultFrom,
			DefaultFromName: cfg.Templates.DefaultFromName,
			BaseURL:         cfg.Templates.BaseURL,
			AssetsURL:       cfg.Templates.AssetsURL,
			UnsubscribeURL:  cfg.Templates.UnsubscribeURL,
		},
		RateLimit: RateLimitConfig{
			Enabled:        cfg.RateLimit.Enabled,
			RequestsPerMin: cfg.RateLimit.RequestsPerMin,
			BurstSize:      cfg.RateLimit.BurstSize,
			WindowSize:     cfg.RateLimit.WindowSize,
		},
		Tracking: TrackingConfig{
			Enabled:        cfg.Tracking.Enabled,
			OpenTracking:   cfg.Tracking.OpenTracking,
			ClickTracking:  cfg.Tracking.ClickTracking,
			TrackingDomain: cfg.Tracking.TrackingDomain,
		},
		Retry: RetryConfig{
			Enabled:      cfg.Retry.Enabled,
			MaxRetries:   cfg.Retry.MaxRetries,
			InitialDelay: cfg.Retry.InitialDelay,
			MaxDelay:     cfg.Retry.MaxDelay,
			Multiplier:   cfg.Retry.Multiplier,
		},
	}

	// Convert providers
	for name, providerCfg := range cfg.Providers {
		emailProviderConfig := ProviderConfig{
			Type:     interfaces.EmailProvider(providerCfg.Type),
			Enabled:  providerCfg.Enabled,
			Priority: providerCfg.Priority,
		}

		// Convert provider-specific configs
		if providerCfg.SMTP != nil {
			emailProviderConfig.SMTP = &interfaces.SMTPConfig{
				Host:       providerCfg.SMTP.Host,
				Port:       providerCfg.SMTP.Port,
				Username:   providerCfg.SMTP.Username,
				Password:   providerCfg.SMTP.Password,
				TLS:        providerCfg.SMTP.TLS,
				StartTLS:   providerCfg.SMTP.StartTLS,
				SkipVerify: providerCfg.SMTP.SkipVerify,
			}
		}

		if providerCfg.SendGrid != nil {
			emailProviderConfig.SendGrid = &interfaces.SendGridConfig{
				APIKey: providerCfg.SendGrid.APIKey,
			}
		}

		if providerCfg.Mailgun != nil {
			emailProviderConfig.Mailgun = &interfaces.MailgunConfig{
				APIKey: providerCfg.Mailgun.APIKey,
				Domain: providerCfg.Mailgun.Domain,
				Region: providerCfg.Mailgun.Region,
			}
		}

		if providerCfg.SES != nil {
			emailProviderConfig.SES = &interfaces.SESConfig{
				Region:          providerCfg.SES.Region,
				AccessKeyID:     providerCfg.SES.AccessKeyID,
				SecretAccessKey: providerCfg.SES.SecretAccessKey,
				SessionToken:    providerCfg.SES.SessionToken,
			}
		}

		if providerCfg.Postmark != nil {
			emailProviderConfig.Postmark = &interfaces.PostmarkConfig{
				APIKey: providerCfg.Postmark.APIKey,
			}
		}

		if providerCfg.Resend != nil {
			emailProviderConfig.Resend = &interfaces.ResendConfig{
				APIKey: providerCfg.Resend.APIKey,
			}
		}

		emailConfig.Providers[name] = emailProviderConfig
	}

	return emailConfig
}
