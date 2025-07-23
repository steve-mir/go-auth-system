# Email Service Documentation

The email service provides comprehensive email functionality for the authentication system, including pre-built templates for common auth flows and support for custom templates with multiple delivery providers.

## Features

- **Multiple Email Providers**: SMTP, SendGrid, Mailgun, AWS SES, Postmark, Resend
- **Pre-built Templates**: Welcome, verification, password reset, login notifications, MFA codes, etc.
- **Custom Templates**: Create and manage your own email templates with variable substitution
- **Bulk Email Support**: Send multiple emails efficiently with batching and rate limiting
- **Email Analytics**: Track delivery, opens, clicks, and bounces
- **Rate Limiting**: Prevent abuse with configurable rate limits
- **Retry Logic**: Automatic retry with exponential backoff for failed emails
- **Health Monitoring**: Built-in health checks for all providers

## Quick Start

### 1. Configuration

Add email configuration to your `config.yaml`:

```yaml
external:
  email:
    enabled: true
    default_provider: "smtp"
    providers:
      smtp:
        type: "smtp"
        enabled: true
        smtp:
          host: "smtp.gmail.com"
          port: 587
          username: "your-email@gmail.com"
          password: "your-app-password"
          start_tls: true
    templates:
      default_from: "noreply@yourapp.com"
      default_from_name: "Your App"
      base_url: "https://yourapp.com"
```

### 2. Environment Variables

You can also configure via environment variables:

```bash
EMAIL_ENABLED=true
EMAIL_DEFAULT_PROVIDER=smtp
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_DEFAULT_FROM=noreply@yourapp.com
```

### 3. Using the Service

```go
// Initialize the email service
emailConfig := email.ConvertConfigToEmailConfig(&config.External.Email)
templates := repository.NewMemoryTemplateRepository()
queue := repository.NewMemoryQueueRepository()
analytics := repository.NewMemoryAnalyticsRepository()

emailService, err := email.NewService(emailConfig, templates, queue, analytics, logger)
if err != nil {
    log.Fatal("Failed to create email service:", err)
}

// Send a welcome email
err = emailService.SendWelcomeEmail(ctx, "user@example.com", "John Doe")

// Send a custom email
req := &email.SendEmailRequest{
    To:       []string{"user@example.com"},
    Subject:  "Custom Email",
    HTMLBody: "<h1>Hello!</h1><p>This is a custom email.</p>",
    TextBody: "Hello!\n\nThis is a custom email.",
}
err = emailService.SendEmail(ctx, req)
```

## API Endpoints

The email service provides REST API endpoints:

### Send Pre-built Emails

- `POST /api/v1/email/send/welcome` - Send welcome email
- `POST /api/v1/email/send/verification` - Send email verification
- `POST /api/v1/email/send/password-reset` - Send password reset
- `POST /api/v1/email/send/login-notification` - Send login notification
- `POST /api/v1/email/send/mfa-code` - Send MFA code
- `POST /api/v1/email/send/account-locked` - Send account locked notification
- `POST /api/v1/email/send/password-changed` - Send password changed confirmation

### Custom Emails

- `POST /api/v1/email/send` - Send custom email
- `POST /api/v1/email/send/bulk` - Send bulk emails

### Template Management

- `POST /api/v1/email/templates` - Create template
- `GET /api/v1/email/templates` - List templates
- `GET /api/v1/email/templates/:id` - Get template
- `PUT /api/v1/email/templates/:id` - Update template
- `DELETE /api/v1/email/templates/:id` - Delete template

### Analytics

- `GET /api/v1/email/analytics/status/:emailId` - Get email status
- `GET /api/v1/email/analytics/reports` - Get email analytics

### Health Check

- `GET /api/v1/email/health` - Check service health

## Examples

### Send Welcome Email

```bash
curl -X POST http://localhost:8080/api/v1/email/send/welcome \
  -H "Content-Type: application/json" \
  -d '{
    "to": "user@example.com",
    "name": "John Doe"
  }'
```

### Send Custom Email

```bash
curl -X POST http://localhost:8080/api/v1/email/send \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["user@example.com"],
    "subject": "Welcome to Our Platform",
    "html_body": "<h1>Welcome!</h1><p>Thanks for joining us.</p>",
    "text_body": "Welcome!\n\nThanks for joining us.",
    "priority": "high"
  }'
```

### Create Custom Template

```bash
curl -X POST http://localhost:8080/api/v1/email/templates \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Product Launch",
    "subject": "🚀 New Product: {{product_name}}",
    "html_body": "<h1>{{product_name}} is here!</h1><p>Hi {{name}}, check out our new product.</p>",
    "text_body": "{{product_name}} is here!\n\nHi {{name}}, check out our new product.",
    "variables": ["name", "product_name"],
    "category": "marketing",
    "is_active": true
  }'
```

### Use Custom Template

```bash
curl -X POST http://localhost:8080/api/v1/email/send \
  -H "Content-Type: application/json" \
  -d '{
    "to": ["user@example.com"],
    "template_id": "template-id-here",
    "variables": {
      "name": "John Doe",
      "product_name": "SuperWidget Pro"
    }
  }'
```

## Provider Configuration

### SMTP (Gmail)

```yaml
smtp:
  type: "smtp"
  enabled: true
  smtp:
    host: "smtp.gmail.com"
    port: 587
    username: "your-email@gmail.com"
    password: "your-app-password"  # Use app password
    start_tls: true
```

### SendGrid

```yaml
sendgrid:
  type: "sendgrid"
  enabled: true
  sendgrid:
    api_key: "SG.your-sendgrid-api-key"
```

### Mailgun

```yaml
mailgun:
  type: "mailgun"
  enabled: true
  mailgun:
    api_key: "your-mailgun-api-key"
    domain: "your-domain.com"
    region: "us"
```

### AWS SES

```yaml
ses:
  type: "ses"
  enabled: true
  ses:
    region: "us-east-1"
    access_key_id: "your-access-key"
    secret_access_key: "your-secret-key"
```

## Pre-built Templates

The service includes these pre-built templates:

1. **Welcome Email** - Greet new users
2. **Email Verification** - Verify email addresses
3. **Password Reset** - Reset forgotten passwords
4. **Login Notification** - Notify of new logins
5. **MFA Code** - Send multi-factor authentication codes
6. **Account Locked** - Notify when account is locked
7. **Password Changed** - Confirm password changes

All templates are responsive and include both HTML and text versions.

## Template Variables

Templates support variable substitution using `{{variable_name}}` syntax:

- `{{name}}` - User's name
- `{{email}}` - User's email
- `{{token}}` - Verification/reset token
- `{{verification_url}}` - Complete verification URL
- `{{reset_url}}` - Complete password reset URL
- `{{app_name}}` - Application name
- `{{base_url}}` - Application base URL

## Rate Limiting

Configure rate limiting to prevent abuse:

```yaml
rate_limit:
  enabled: true
  requests_per_minute: 100
  burst_size: 20
  window_size: "1m"
```

## Email Tracking

Enable tracking to monitor email performance:

```yaml
tracking:
  enabled: true
  open_tracking: true
  click_tracking: true
  tracking_domain: "track.yourapp.com"
```

## Retry Configuration

Configure automatic retries for failed emails:

```yaml
retry:
  enabled: true
  max_retries: 3
  initial_delay: "30s"
  max_delay: "10m"
  multiplier: 2.0
```

## Testing

For testing, you can use MailHog to capture emails locally:

```bash
# Run MailHog
docker run -p 1025:1025 -p 8025:8025 mailhog/mailhog

# Configure SMTP to use MailHog
smtp:
  host: "localhost"
  port: 1025
  username: ""
  password: ""
  tls: false
```

Then view emails at http://localhost:8025

## Production Considerations

1. **Use App Passwords**: For Gmail, use app-specific passwords instead of your regular password
2. **Environment Variables**: Store sensitive credentials in environment variables
3. **Provider Failover**: Configure multiple providers for redundancy
4. **Rate Limits**: Set appropriate rate limits based on your provider's limits
5. **Monitoring**: Monitor email delivery rates and set up alerts
6. **Templates**: Test templates thoroughly before deploying
7. **Unsubscribe**: Include unsubscribe links in marketing emails

## Troubleshooting

### Common Issues

1. **SMTP Authentication Failed**
   - Check username/password
   - Enable "Less secure app access" for Gmail (not recommended)
   - Use app-specific passwords

2. **Emails Not Sending**
   - Check provider configuration
   - Verify network connectivity
   - Check rate limits

3. **Templates Not Found**
   - Ensure templates are created and active
   - Check template IDs

4. **High Bounce Rate**
   - Verify email addresses
   - Check sender reputation
   - Review email content for spam triggers

### Health Check

Use the health check endpoint to verify service status:

```bash
curl http://localhost:8080/api/v1/email/health
```

This will test connectivity to all configured providers.