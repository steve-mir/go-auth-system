package postgres

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/lib/pq"
	"github.com/steve-mir/go-auth-system/internal/service/admin"
)

// NotificationRepository implements the admin.NotificationRepository interface
type NotificationRepository struct {
	db *sql.DB
}

// NewNotificationRepository creates a new notification repository
func NewNotificationRepository(db *sql.DB) *NotificationRepository {
	return &NotificationRepository{
		db: db,
	}
}

// GetNotificationSettings retrieves notification settings
func (r *NotificationRepository) GetNotificationSettings(ctx context.Context) (*admin.NotificationSettings, error) {
	query := `
		SELECT 
			email_enabled, email_recipients, slack_enabled, slack_webhook,
			sms_enabled, sms_recipients, thresholds
		FROM notification_settings
		WHERE id = 1
	`

	var settings admin.NotificationSettings
	var emailRecipients pq.StringArray
	var smsRecipients pq.StringArray
	var thresholdsJSON []byte
	var slackWebhook sql.NullString

	err := r.db.QueryRowContext(ctx, query).Scan(
		&settings.EmailEnabled,
		&emailRecipients,
		&settings.SlackEnabled,
		&slackWebhook,
		&settings.SMSEnabled,
		&smsRecipients,
		&thresholdsJSON,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			// Return default settings if none exist
			return r.getDefaultNotificationSettings(), nil
		}
		return nil, fmt.Errorf("failed to get notification settings: %w", err)
	}

	settings.EmailRecipients = []string(emailRecipients)
	settings.SMSRecipients = []string(smsRecipients)

	if slackWebhook.Valid {
		settings.SlackWebhook = slackWebhook.String
	}

	if len(thresholdsJSON) > 0 {
		if err := json.Unmarshal(thresholdsJSON, &settings.Thresholds); err != nil {
			return nil, fmt.Errorf("failed to unmarshal thresholds: %w", err)
		}
	} else {
		settings.Thresholds = r.getDefaultThresholds()
	}

	return &settings, nil
}

// UpdateNotificationSettings updates notification settings
func (r *NotificationRepository) UpdateNotificationSettings(ctx context.Context, req *admin.UpdateNotificationSettingsRequest) error {
	// First, get current settings
	currentSettings, err := r.GetNotificationSettings(ctx)
	if err != nil {
		return fmt.Errorf("failed to get current settings: %w", err)
	}

	// Update fields if provided
	if req.EmailEnabled != nil {
		currentSettings.EmailEnabled = *req.EmailEnabled
	}
	if req.EmailRecipients != nil {
		currentSettings.EmailRecipients = req.EmailRecipients
	}
	if req.SlackEnabled != nil {
		currentSettings.SlackEnabled = *req.SlackEnabled
	}
	if req.SlackWebhook != nil {
		currentSettings.SlackWebhook = *req.SlackWebhook
	}
	if req.SMSEnabled != nil {
		currentSettings.SMSEnabled = *req.SMSEnabled
	}
	if req.SMSRecipients != nil {
		currentSettings.SMSRecipients = req.SMSRecipients
	}
	if req.Thresholds != nil {
		currentSettings.Thresholds = *req.Thresholds
	}

	// Marshal thresholds
	thresholdsJSON, err := json.Marshal(currentSettings.Thresholds)
	if err != nil {
		return fmt.Errorf("failed to marshal thresholds: %w", err)
	}

	// Upsert the settings
	query := `
		INSERT INTO notification_settings (
			id, email_enabled, email_recipients, slack_enabled, slack_webhook,
			sms_enabled, sms_recipients, thresholds, updated_at
		) VALUES (
			1, $1, $2, $3, $4, $5, $6, $7, NOW()
		)
		ON CONFLICT (id) DO UPDATE SET
			email_enabled = EXCLUDED.email_enabled,
			email_recipients = EXCLUDED.email_recipients,
			slack_enabled = EXCLUDED.slack_enabled,
			slack_webhook = EXCLUDED.slack_webhook,
			sms_enabled = EXCLUDED.sms_enabled,
			sms_recipients = EXCLUDED.sms_recipients,
			thresholds = EXCLUDED.thresholds,
			updated_at = NOW()
	`

	var slackWebhook interface{}
	if currentSettings.SlackWebhook != "" {
		slackWebhook = currentSettings.SlackWebhook
	}

	_, err = r.db.ExecContext(ctx, query,
		currentSettings.EmailEnabled,
		pq.Array(currentSettings.EmailRecipients),
		currentSettings.SlackEnabled,
		slackWebhook,
		currentSettings.SMSEnabled,
		pq.Array(currentSettings.SMSRecipients),
		thresholdsJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to update notification settings: %w", err)
	}

	return nil
}

// CreateNotificationSettings creates initial notification settings
func (r *NotificationRepository) CreateNotificationSettings(ctx context.Context, settings *admin.NotificationSettings) error {
	thresholdsJSON, err := json.Marshal(settings.Thresholds)
	if err != nil {
		return fmt.Errorf("failed to marshal thresholds: %w", err)
	}

	query := `
		INSERT INTO notification_settings (
			id, email_enabled, email_recipients, slack_enabled, slack_webhook,
			sms_enabled, sms_recipients, thresholds, created_at, updated_at
		) VALUES (
			1, $1, $2, $3, $4, $5, $6, $7, NOW(), NOW()
		)
	`

	var slackWebhook interface{}
	if settings.SlackWebhook != "" {
		slackWebhook = settings.SlackWebhook
	}

	_, err = r.db.ExecContext(ctx, query,
		settings.EmailEnabled,
		pq.Array(settings.EmailRecipients),
		settings.SlackEnabled,
		slackWebhook,
		settings.SMSEnabled,
		pq.Array(settings.SMSRecipients),
		thresholdsJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to create notification settings: %w", err)
	}

	return nil
}

// getDefaultNotificationSettings returns default notification settings
func (r *NotificationRepository) getDefaultNotificationSettings() *admin.NotificationSettings {
	return &admin.NotificationSettings{
		EmailEnabled:    false,
		EmailRecipients: []string{},
		SlackEnabled:    false,
		SlackWebhook:    "",
		SMSEnabled:      false,
		SMSRecipients:   []string{},
		Thresholds:      r.getDefaultThresholds(),
	}
}

// getDefaultThresholds returns default notification thresholds
func (r *NotificationRepository) getDefaultThresholds() admin.NotificationThresholds {
	return admin.NotificationThresholds{
		FailedLoginRate:     10.0, // 10% failed login rate
		ErrorRate:           5.0,  // 5% error rate
		ResponseTime:        1000, // 1000ms response time
		DatabaseConnections: 80,   // 80% of max connections
		MemoryUsage:         85.0, // 85% memory usage
		CPUUsage:            80.0, // 80% CPU usage
	}
}
