package email

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/steve-mir/go-auth-system/internal/service/email/repository"
)

func TestEmailService(t *testing.T) {
	// Create test configuration
	config := &EmailConfig{
		DefaultProvider: ProviderSMTP,
		Providers: map[string]ProviderConfig{
			"smtp": {
				Type:    ProviderSMTP,
				Enabled: true,
				SMTP: &SMTPConfig{
					Host:     "localhost",
					Port:     1025, // MailHog test server
					Username: "test@example.com",
					Password: "",
					TLS:      false,
					StartTLS: false,
				},
			},
		},
		Templates: TemplateConfig{
			DefaultFrom:     "test@example.com",
			DefaultFromName: "Test App",
			BaseURL:         "https://test.example.com",
		},
		RateLimit: RateLimitConfig{
			Enabled:        false,
			RequestsPerMin: 60,
			BurstSize:      10,
		},
		Tracking: TrackingConfig{
			Enabled: false,
		},
		Retry: RetryConfig{
			Enabled:      true,
			MaxRetries:   3,
			InitialDelay: time.Second,
			MaxDelay:     time.Minute,
			Multiplier:   2.0,
		},
	}

	// Create repositories
	templates := repository.NewMemoryTemplateRepository()
	queue := repository.NewMemoryQueueRepository()
	analytics := repository.NewMemoryAnalyticsRepository()

	// Create logger
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// Create service
	service, err := NewService(config, templates, queue, analytics, logger)
	if err != nil {
		t.Fatalf("Failed to create email service: %v", err)
	}

	ctx := context.Background()

	t.Run("SendWelcomeEmail", func(t *testing.T) {
		err := service.SendWelcomeEmail(ctx, "user@example.com", "John Doe")
		if err != nil {
			t.Errorf("Failed to send welcome email: %v", err)
		}
	})

	t.Run("SendVerificationEmail", func(t *testing.T) {
		err := service.SendVerificationEmail(ctx, "user@example.com", "John Doe", "test-token-123")
		if err != nil {
			t.Errorf("Failed to send verification email: %v", err)
		}
	})

	t.Run("SendCustomEmail", func(t *testing.T) {
		req := &SendEmailRequest{
			To:       []string{"user@example.com"},
			Subject:  "Test Email",
			HTMLBody: "<h1>Hello World</h1><p>This is a test email.</p>",
			TextBody: "Hello World\n\nThis is a test email.",
		}

		err := service.SendEmail(ctx, req)
		if err != nil {
			t.Errorf("Failed to send custom email: %v", err)
		}
	})

	t.Run("CreateCustomTemplate", func(t *testing.T) {
		template := &EmailTemplate{
			Name:        "Custom Test Template",
			Description: "A custom template for testing",
			Subject:     "Welcome {{name}}!",
			HTMLBody:    "<h1>Welcome {{name}}!</h1><p>Thanks for joining {{app_name}}.</p>",
			TextBody:    "Welcome {{name}}!\n\nThanks for joining {{app_name}}.",
			Variables:   []string{"name", "app_name"},
			Category:    "test",
			IsActive:    true,
		}

		err := service.CreateTemplate(ctx, template)
		if err != nil {
			t.Errorf("Failed to create template: %v", err)
		}

		// Test using the custom template
		req := &SendEmailRequest{
			To:         []string{"user@example.com"},
			TemplateID: template.ID,
			Variables: map[string]string{
				"name":     "Jane Doe",
				"app_name": "Test App",
			},
		}

		err = service.SendEmail(ctx, req)
		if err != nil {
			t.Errorf("Failed to send email with custom template: %v", err)
		}
	})

	t.Run("ListTemplates", func(t *testing.T) {
		templates, err := service.ListTemplates(ctx, &TemplateFilter{
			Category: "authentication",
			IsActive: boolPtr(true),
		})
		if err != nil {
			t.Errorf("Failed to list templates: %v", err)
		}

		if len(templates) == 0 {
			t.Error("Expected to find authentication templates")
		}
	})

	t.Run("HealthCheck", func(t *testing.T) {
		// Note: This will fail if no SMTP server is running on localhost:1025
		// You can use MailHog for testing: docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog
		err := service.HealthCheck(ctx)
		if err != nil {
			t.Logf("Health check failed (expected if no test SMTP server): %v", err)
		}
	})
}

func boolPtr(b bool) *bool {
	return &b
}
