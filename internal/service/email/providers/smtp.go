package providers

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"strings"

	"github.com/steve-mir/go-auth-system/internal/service/email"
)

// SMTPProvider implements email sending via SMTP
type SMTPProvider struct {
	config *email.SMTPConfig
}

// NewSMTPProvider creates a new SMTP provider
func NewSMTPProvider(config *email.SMTPConfig) (*SMTPProvider, error) {
	if config == nil {
		return nil, fmt.Errorf("SMTP config is required")
	}

	return &SMTPProvider{
		config: config,
	}, nil
}

// SendEmail sends an email via SMTP
func (p *SMTPProvider) SendEmail(ctx context.Context, req *email.SendEmailRequest) error {
	// Build message
	message, err := p.buildMessage(req)
	if err != nil {
		return fmt.Errorf("failed to build message: %w", err)
	}

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)

	var client *smtp.Client
	var conn interface{}

	if p.config.TLS {
		// Direct TLS connection
		tlsConfig := &tls.Config{
			ServerName:         p.config.Host,
			InsecureSkipVerify: p.config.SkipVerify,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to connect with TLS: %w", err)
		}
		defer conn.Close()

		client, err = smtp.NewClient(conn, p.config.Host)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
	} else {
		// Plain connection
		client, err = smtp.Dial(addr)
		if err != nil {
			return fmt.Errorf("failed to connect to SMTP server: %w", err)
		}
	}
	defer client.Close()

	// STARTTLS if configured
	if p.config.StartTLS && !p.config.TLS {
		tlsConfig := &tls.Config{
			ServerName:         p.config.Host,
			InsecureSkipVerify: p.config.SkipVerify,
		}

		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to start TLS: %w", err)
		}
	}

	// Authentication
	if p.config.Username != "" && p.config.Password != "" {
		auth := smtp.PlainAuth("", p.config.Username, p.config.Password, p.config.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication failed: %w", err)
		}
	}

	// Set sender
	from := req.From
	if from == "" {
		from = p.config.Username
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Set recipients
	allRecipients := append(req.To, req.CC...)
	allRecipients = append(allRecipients, req.BCC...)

	for _, recipient := range allRecipients {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("failed to set recipient %s: %w", recipient, err)
		}
	}

	// Send message
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to get data writer: %w", err)
	}
	defer writer.Close()

	if _, err := writer.Write([]byte(message)); err != nil {
		return fmt.Errorf("failed to write message: %w", err)
	}

	return nil
}

// HealthCheck checks if the SMTP server is reachable
func (p *SMTPProvider) HealthCheck(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", p.config.Host, p.config.Port)

	client, err := smtp.Dial(addr)
	if err != nil {
		return fmt.Errorf("SMTP health check failed: %w", err)
	}
	defer client.Close()

	return nil
}

// GetName returns the provider name
func (p *SMTPProvider) GetName() string {
	return "SMTP"
}

// GetType returns the provider type
func (p *SMTPProvider) GetType() email.EmailProvider {
	return email.ProviderSMTP
}

// buildMessage builds the email message
func (p *SMTPProvider) buildMessage(req *email.SendEmailRequest) (string, error) {
	var message strings.Builder

	// Headers
	from := req.From
	if from == "" {
		from = p.config.Username
	}

	if req.FromName != "" {
		message.WriteString(fmt.Sprintf("From: %s <%s>\r\n", req.FromName, from))
	} else {
		message.WriteString(fmt.Sprintf("From: %s\r\n", from))
	}

	message.WriteString(fmt.Sprintf("To: %s\r\n", strings.Join(req.To, ", ")))

	if len(req.CC) > 0 {
		message.WriteString(fmt.Sprintf("Cc: %s\r\n", strings.Join(req.CC, ", ")))
	}

	message.WriteString(fmt.Sprintf("Subject: %s\r\n", req.Subject))
	message.WriteString("MIME-Version: 1.0\r\n")

	// Content type
	if req.HTMLBody != "" && req.TextBody != "" {
		// Multipart message
		boundary := "boundary123456789"
		message.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s\r\n", boundary))
		message.WriteString("\r\n")

		// Text part
		message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		message.WriteString("\r\n")
		message.WriteString(req.TextBody)
		message.WriteString("\r\n")

		// HTML part
		message.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		message.WriteString("\r\n")
		message.WriteString(req.HTMLBody)
		message.WriteString("\r\n")

		message.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else if req.HTMLBody != "" {
		// HTML only
		message.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		message.WriteString("\r\n")
		message.WriteString(req.HTMLBody)
	} else {
		// Text only
		message.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		message.WriteString("\r\n")
		message.WriteString(req.TextBody)
	}

	return message.String(), nil
}
