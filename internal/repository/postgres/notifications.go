package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
	"github.com/steve-mir/go-auth-system/internal/service/admin"
)

// NotificationRepository implements the admin.NotificationRepository interface using SQLC
type NotificationRepository struct {
	queries *db.Queries
}

// NewNotificationRepository creates a new notification repository using SQLC
func NewNotificationRepository(queries *db.Queries) *NotificationRepository {
	return &NotificationRepository{
		queries: queries,
	}
}

// GetNotificationSettings retrieves notification settings
func (r *NotificationRepository) GetNotificationSettings(ctx context.Context) (*admin.NotificationSettings, error) {
	dbSettings, err := r.queries.GetNotificationSettings(ctx)
	if err != nil {
		// Return default settings if none exist
		return r.getDefaultNotificationSettings(), nil
	}

	settings := &admin.NotificationSettings{
		EmailEnabled:    dbSettings.EmailEnabled.Bool,
		EmailRecipients: dbSettings.EmailRecipients,
		SlackEnabled:    dbSettings.SlackEnabled.Bool,
		SMSEnabled:      dbSettings.SmsEnabled.Bool,
		SMSRecipients:   dbSettings.SmsRecipients,
	}

	if dbSettings.SlackWebhook.Valid {
		settings.SlackWebhook = dbSettings.SlackWebhook.String
	}

	if len(dbSettings.Thresholds) > 0 {
		if err := json.Unmarshal(dbSettings.Thresholds, &settings.Thresholds); err != nil {
			return nil, fmt.Errorf("failed to unmarshal thresholds: %w", err)
		}
	} else {
		settings.Thresholds = r.getDefaultThresholds()
	}

	return settings, nil
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

	// Prepare parameters
	params := db.UpsertNotificationSettingsParams{
		EmailEnabled:    pgtype.Bool{Bool: currentSettings.EmailEnabled, Valid: true},
		EmailRecipients: currentSettings.EmailRecipients,
		SlackEnabled:    pgtype.Bool{Bool: currentSettings.SlackEnabled, Valid: true},
		SlackWebhook:    pgtype.Text{String: currentSettings.SlackWebhook, Valid: currentSettings.SlackWebhook != ""},
		SmsEnabled:      pgtype.Bool{Bool: currentSettings.SMSEnabled, Valid: true},
		SmsRecipients:   currentSettings.SMSRecipients,
		Thresholds:      thresholdsJSON,
	}

	err = r.queries.UpsertNotificationSettings(ctx, params)
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

	params := db.CreateNotificationSettingsParams{
		EmailEnabled:    pgtype.Bool{Bool: settings.EmailEnabled, Valid: true},
		EmailRecipients: settings.EmailRecipients,
		SlackEnabled:    pgtype.Bool{Bool: settings.SlackEnabled, Valid: true},
		SlackWebhook:    pgtype.Text{String: settings.SlackWebhook, Valid: settings.SlackWebhook != ""},
		SmsEnabled:      pgtype.Bool{Bool: settings.SMSEnabled, Valid: true},
		SmsRecipients:   settings.SMSRecipients,
		Thresholds:      thresholdsJSON,
	}

	err = r.queries.CreateNotificationSettings(ctx, params)
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
