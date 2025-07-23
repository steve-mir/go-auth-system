-- name: GetNotificationSettings :one
SELECT 
    email_enabled, email_recipients, slack_enabled, slack_webhook,
    sms_enabled, sms_recipients, thresholds
FROM notification_settings
WHERE id = 1;

-- name: UpsertNotificationSettings :exec
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
    updated_at = NOW();

-- name: CreateNotificationSettings :exec
INSERT INTO notification_settings (
    id, email_enabled, email_recipients, slack_enabled, slack_webhook,
    sms_enabled, sms_recipients, thresholds, created_at, updated_at
) VALUES (
    1, $1, $2, $3, $4, $5, $6, $7, NOW(), NOW()
);