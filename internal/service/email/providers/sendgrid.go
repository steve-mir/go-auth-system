package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/steve-mir/go-auth-system/internal/interfaces"
)

// SendGridProvider implements email sending via SendGrid API
type SendGridProvider struct {
	config *interfaces.SendGridConfig
	client *http.Client
}

// NewSendGridProvider creates a new SendGrid provider
func NewSendGridProvider(config *interfaces.SendGridConfig) (*SendGridProvider, error) {
	if config == nil || config.APIKey == "" {
		return nil, fmt.Errorf("SendGrid API key is required")
	}

	return &SendGridProvider{
		config: config,
		client: &http.Client{},
	}, nil
}

// SendEmail sends an email via SendGrid API
func (p *SendGridProvider) SendEmail(ctx context.Context, req *interfaces.SendEmailRequest) error {
	payload := p.buildSendGridPayload(req)

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal SendGrid payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", "https://api.sendgrid.com/v3/mail/send", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+p.config.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("failed to send request to SendGrid: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("SendGrid API error: status %d", resp.StatusCode)
	}

	return nil
}

// HealthCheck checks if SendGrid API is accessible
func (p *SendGridProvider) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://api.sendgrid.com/v3/user/profile", nil)
	if err != nil {
		return fmt.Errorf("failed to create health check request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+p.config.APIKey)

	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("SendGrid health check failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("SendGrid health check failed: status %d", resp.StatusCode)
	}

	return nil
}

// GetName returns the provider name
func (p *SendGridProvider) GetName() string {
	return "SendGrid"
}

// GetType returns the provider type
func (p *SendGridProvider) GetType() interfaces.EmailProvider {
	return interfaces.ProviderSendGrid
}

// SendGrid API payload structures
type sendGridPayload struct {
	Personalizations []sendGridPersonalization `json:"personalizations"`
	From             sendGridEmail             `json:"from"`
	Subject          string                    `json:"subject"`
	Content          []sendGridContent         `json:"content"`
	Attachments      []sendGridAttachment      `json:"attachments,omitempty"`
}

type sendGridPersonalization struct {
	To  []sendGridEmail `json:"to"`
	CC  []sendGridEmail `json:"cc,omitempty"`
	BCC []sendGridEmail `json:"bcc,omitempty"`
}

type sendGridEmail struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

type sendGridContent struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type sendGridAttachment struct {
	Content     string `json:"content"`
	Type        string `json:"type"`
	Filename    string `json:"filename"`
	Disposition string `json:"disposition,omitempty"`
	ContentID   string `json:"content_id,omitempty"`
}

func (p *SendGridProvider) buildSendGridPayload(req *interfaces.SendEmailRequest) *sendGridPayload {
	payload := &sendGridPayload{
		Subject: req.Subject,
	}

	// From
	payload.From = sendGridEmail{
		Email: req.From,
		Name:  req.FromName,
	}

	// Personalizations
	personalization := sendGridPersonalization{}

	for _, to := range req.To {
		personalization.To = append(personalization.To, sendGridEmail{Email: to})
	}

	for _, cc := range req.CC {
		personalization.CC = append(personalization.CC, sendGridEmail{Email: cc})
	}

	for _, bcc := range req.BCC {
		personalization.BCC = append(personalization.BCC, sendGridEmail{Email: bcc})
	}

	payload.Personalizations = []sendGridPersonalization{personalization}

	// Content
	if req.TextBody != "" {
		payload.Content = append(payload.Content, sendGridContent{
			Type:  "text/plain",
			Value: req.TextBody,
		})
	}

	if req.HTMLBody != "" {
		payload.Content = append(payload.Content, sendGridContent{
			Type:  "text/html",
			Value: req.HTMLBody,
		})
	}

	// Attachments
	for _, att := range req.Attachments {
		sgAtt := sendGridAttachment{
			Content:  string(att.Content), // Should be base64 encoded
			Type:     att.ContentType,
			Filename: att.Filename,
		}

		if att.Inline {
			sgAtt.Disposition = "inline"
			sgAtt.ContentID = att.ContentID
		}

		payload.Attachments = append(payload.Attachments, sgAtt)
	}

	return payload
}
