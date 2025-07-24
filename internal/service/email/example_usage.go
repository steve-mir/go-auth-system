package email

// import (
// 	"context"
// 	"fmt"
// 	"log/slog"
// 	"os"
// 	"time"

// 	"github.com/steve-mir/go-auth-system/internal/service/email/repository"
// )

// // ExampleEmailService demonstrates how to use the email service
// func ExampleEmailService() {
// 	// Create email service configuration
// 	config := &EmailConfig{
// 		DefaultProvider: ProviderSMTP,
// 		Providers: map[string]ProviderConfig{
// 			"smtp": {
// 				Type:    ProviderSMTP,
// 				Enabled: true,
// 				SMTP: &SMTPConfig{
// 					Host:     "smtp.gmail.com",
// 					Port:     587,
// 					Username: "your-email@gmail.com",
// 					Password: "your-app-password",
// 					TLS:      false,
// 					StartTLS: true,
// 				},
// 			},
// 			"sendgrid": {
// 				Type:    ProviderSendGrid,
// 				Enabled: false, // Disabled for this example
// 				SendGrid: &SendGridConfig{
// 					APIKey: "your-sendgrid-api-key",
// 				},
// 			},
// 		},
// 		Templates: TemplateConfig{
// 			DefaultFrom:     "noreply@yourapp.com",
// 			DefaultFromName: "Your App",
// 			BaseURL:         "https://yourapp.com",
// 			AssetsURL:       "https://assets.yourapp.com",
// 			UnsubscribeURL:  "https://yourapp.com/unsubscribe",
// 		},
// 		RateLimit: RateLimitConfig{
// 			Enabled:        true,
// 			RequestsPerMin: 100,
// 			BurstSize:      20,
// 			WindowSize:     time.Minute,
// 		},
// 		Tracking: TrackingConfig{
// 			Enabled:        true,
// 			OpenTracking:   true,
// 			ClickTracking:  true,
// 			TrackingDomain: "track.yourapp.com",
// 		},
// 		Retry: RetryConfig{
// 			Enabled:      true,
// 			MaxRetries:   3,
// 			InitialDelay: 30 * time.Second,
// 			MaxDelay:     10 * time.Minute,
// 			Multiplier:   2.0,
// 		},
// 	}

// 	// Create repositories (in production, use database implementations)
// 	templates := repository.NewMemoryTemplateRepository()
// 	queue := repository.NewMemoryQueueRepository()
// 	analytics := repository.NewMemoryAnalyticsRepository()

// 	// Create logger
// 	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

// 	// Create email service
// 	emailService, err := NewService(config, templates, queue, analytics, logger)
// 	if err != nil {
// 		fmt.Printf("Failed to create email service: %v\n", err)
// 		return
// 	}

// 	ctx := context.Background()

// 	// Example 1: Send welcome email using prebuilt template
// 	fmt.Println("=== Example 1: Welcome Email ===")
// 	err = emailService.SendWelcomeEmail(ctx, "user@example.com", "John Doe")
// 	if err != nil {
// 		fmt.Printf("Failed to send welcome email: %v\n", err)
// 	} else {
// 		fmt.Println("Welcome email sent successfully!")
// 	}

// 	// Example 2: Send verification email
// 	fmt.Println("\n=== Example 2: Verification Email ===")
// 	verificationToken := "abc123def456"
// 	err = emailService.SendVerificationEmail(ctx, "user@example.com", "John Doe", verificationToken)
// 	if err != nil {
// 		fmt.Printf("Failed to send verification email: %v\n", err)
// 	} else {
// 		fmt.Println("Verification email sent successfully!")
// 	}

// 	// Example 3: Send custom email
// 	fmt.Println("\n=== Example 3: Custom Email ===")
// 	customEmail := &SendEmailRequest{
// 		To:      []string{"user@example.com"},
// 		CC:      []string{"manager@example.com"},
// 		Subject: "Important Update",
// 		HTMLBody: `
// 			<h2>Important System Update</h2>
// 			<p>Dear User,</p>
// 			<p>We're excited to announce new features in our system:</p>
// 			<ul>
// 				<li>Enhanced security</li>
// 				<li>Improved performance</li>
// 				<li>New dashboard</li>
// 			</ul>
// 			<p>Best regards,<br>The Team</p>
// 		`,
// 		TextBody: `
// Important System Update

// Dear User,

// We're excited to announce new features in our system:
// - Enhanced security
// - Improved performance
// - New dashboard

// Best regards,
// The Team
// 		`,
// 		Priority: PriorityHigh,
// 		Tags:     []string{"announcement", "features"},
// 	}

// 	err = emailService.SendEmail(ctx, customEmail)
// 	if err != nil {
// 		fmt.Printf("Failed to send custom email: %v\n", err)
// 	} else {
// 		fmt.Println("Custom email sent successfully!")
// 	}

// 	// Example 4: Create and use custom template
// 	fmt.Println("\n=== Example 4: Custom Template ===")
// 	customTemplate := &EmailTemplate{
// 		Name:        "Product Launch",
// 		Description: "Template for product launch announcements",
// 		Subject:     "🚀 Introducing {{product_name}}!",
// 		HTMLBody: `
// 			<div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
// 				<h1 style="color: #2c3e50;">🚀 Introducing {{product_name}}!</h1>
// 				<p>Hi {{customer_name}},</p>
// 				<p>We're thrilled to announce the launch of our latest product: <strong>{{product_name}}</strong>!</p>
// 				<div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
// 					<h3>Key Features:</h3>
// 					<p>{{features}}</p>
// 				</div>
// 				<div style="text-align: center; margin: 30px 0;">
// 					<a href="{{product_url}}" style="background: #3498db; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px;">
// 						Learn More
// 					</a>
// 				</div>
// 				<p>Thanks for being a valued customer!</p>
// 			</div>
// 		`,
// 		TextBody: `
// 🚀 Introducing {{product_name}}!

// Hi {{customer_name}},

// We're thrilled to announce the launch of our latest product: {{product_name}}!

// Key Features:
// {{features}}

// Learn more: {{product_url}}

// Thanks for being a valued customer!
// 		`,
// 		Variables: []string{"customer_name", "product_name", "features", "product_url"},
// 		Category:  "marketing",
// 		Tags:      []string{"product-launch", "announcement"},
// 		IsActive:  true,
// 	}

// 	err = emailService.CreateTemplate(ctx, customTemplate)
// 	if err != nil {
// 		fmt.Printf("Failed to create custom template: %v\n", err)
// 	} else {
// 		fmt.Println("Custom template created successfully!")

// 		// Use the custom template
// 		templateEmail := &SendEmailRequest{
// 			To:         []string{"customer@example.com"},
// 			TemplateID: customTemplate.ID,
// 			Variables: map[string]string{
// 				"customer_name": "Alice Johnson",
// 				"product_name":  "SuperWidget Pro",
// 				"features":      "Advanced analytics, Real-time sync, Mobile app",
// 				"product_url":   "https://yourapp.com/products/superwidget-pro",
// 			},
// 			Tags: []string{"product-launch"},
// 		}

// 		err = emailService.SendEmail(ctx, templateEmail)
// 		if err != nil {
// 			fmt.Printf("Failed to send template email: %v\n", err)
// 		} else {
// 			fmt.Println("Template email sent successfully!")
// 		}
// 	}

// 	// Example 5: Send bulk emails
// 	fmt.Println("\n=== Example 5: Bulk Emails ===")
// 	bulkEmails := []*SendEmailRequest{
// 		{
// 			To:         []string{"user1@example.com"},
// 			TemplateID: DefaultPrebuiltTemplates().Welcome,
// 			Variables:  map[string]string{"name": "User One"},
// 		},
// 		{
// 			To:         []string{"user2@example.com"},
// 			TemplateID: DefaultPrebuiltTemplates().Welcome,
// 			Variables:  map[string]string{"name": "User Two"},
// 		},
// 		{
// 			To:         []string{"user3@example.com"},
// 			TemplateID: DefaultPrebuiltTemplates().Welcome,
// 			Variables:  map[string]string{"name": "User Three"},
// 		},
// 	}

// 	bulkRequest := &BulkEmailRequest{
// 		Emails:       bulkEmails,
// 		BatchSize:    2,
// 		DelayBetween: 1 * time.Second,
// 	}

// 	err = emailService.SendBulkEmails(ctx, bulkRequest)
// 	if err != nil {
// 		fmt.Printf("Failed to send bulk emails: %v\n", err)
// 	} else {
// 		fmt.Println("Bulk emails sent successfully!")
// 	}

// 	// Example 6: List templates
// 	fmt.Println("\n=== Example 6: List Templates ===")
// 	templates_list, err := emailService.ListTemplates(ctx, &TemplateFilter{
// 		Category: "authentication",
// 		IsActive: &[]bool{true}[0],
// 		Limit:    10,
// 	})
// 	if err != nil {
// 		fmt.Printf("Failed to list templates: %v\n", err)
// 	} else {
// 		fmt.Printf("Found %d authentication templates:\n", len(templates_list))
// 		for _, tmpl := range templates_list {
// 			fmt.Printf("- %s: %s\n", tmpl.ID, tmpl.Name)
// 		}
// 	}

// 	// Example 7: Health check
// 	fmt.Println("\n=== Example 7: Health Check ===")
// 	err = emailService.HealthCheck(ctx)
// 	if err != nil {
// 		fmt.Printf("Email service health check failed: %v\n", err)
// 	} else {
// 		fmt.Println("Email service is healthy!")
// 	}

// 	fmt.Println("\n=== Email Service Examples Complete ===")
// }

// // ExampleConfiguration shows different configuration examples
// func ExampleConfiguration() {
// 	fmt.Println("=== Email Service Configuration Examples ===")

// 	// SMTP Configuration
// 	fmt.Println("\n1. SMTP Configuration (Gmail):")
// 	fmt.Println(`
// email:
//   enabled: true
//   default_provider: "smtp"
//   providers:
//     smtp:
//       type: "smtp"
//       enabled: true
//       smtp:
//         host: "smtp.gmail.com"
//         port: 587
//         username: "your-email@gmail.com"
//         password: "your-app-password"
//         tls: false
//         start_tls: true
// `)

// 	// SendGrid Configuration
// 	fmt.Println("\n2. SendGrid Configuration:")
// 	fmt.Println(`
// email:
//   enabled: true
//   default_provider: "sendgrid"
//   providers:
//     sendgrid:
//       type: "sendgrid"
//       enabled: true
//       sendgrid:
//         api_key: "SG.your-sendgrid-api-key"
// `)

// 	// Multiple Providers Configuration
// 	fmt.Println("\n3. Multiple Providers Configuration:")
// 	fmt.Println(`
// email:
//   enabled: true
//   default_provider: "sendgrid"
//   providers:
//     sendgrid:
//       type: "sendgrid"
//       enabled: true
//       priority: 1
//       sendgrid:
//         api_key: "SG.your-sendgrid-api-key"
//     smtp:
//       type: "smtp"
//       enabled: true
//       priority: 2
//       smtp:
//         host: "smtp.gmail.com"
//         port: 587
//         username: "backup@gmail.com"
//         password: "backup-password"
//         start_tls: true
//   templates:
//     default_from: "noreply@yourapp.com"
//     default_from_name: "Your App"
//     base_url: "https://yourapp.com"
//   rate_limit:
//     enabled: true
//     requests_per_minute: 100
//     burst_size: 20
//   tracking:
//     enabled: true
//     open_tracking: true
//     click_tracking: true
//   retry:
//     enabled: true
//     max_retries: 3
//     initial_delay: "30s"
//     max_delay: "10m"
//     multiplier: 2.0
// `)
// }
