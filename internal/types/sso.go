package types

import (
	"time"
)

// SocialAccount represents a social account linked to a user
type SocialAccount struct {
	ID           string            `json:"id"`
	UserID       string            `json:"user_id"`
	Provider     string            `json:"provider"`
	SocialID     string            `json:"social_id"`
	Email        string            `json:"email"`
	Name         string            `json:"name"`
	AccessToken  string            `json:"access_token,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time        `json:"expires_at,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}
