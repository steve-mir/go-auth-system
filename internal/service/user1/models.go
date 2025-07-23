package user1

import (
	"time"

	"github.com/google/uuid"
)

// UserProfile represents user profile information
type UserProfile struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username,omitempty"`
	FirstName string    `json:"first_name,omitempty"`
	LastName  string    `json:"last_name,omitempty"`
	Phone     string    `json:"phone,omitempty"`
	Roles     []string  `json:"roles,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Verified  struct {
		Email bool `json:"email"`
		Phone bool `json:"phone"`
	} `json:"verified"`
	Status struct {
		Locked         bool       `json:"locked"`
		FailedAttempts int32      `json:"failed_attempts"`
		LastLogin      *time.Time `json:"last_login,omitempty"`
	} `json:"status"`
}

// UpdateProfileRequest represents a profile update request
type UpdateProfileRequest struct {
	Email     *string `json:"email,omitempty" validate:"omitempty,email"`
	Username  *string `json:"username,omitempty" validate:"omitempty,min=3,max=50"`
	FirstName *string `json:"first_name,omitempty" validate:"omitempty,max=100"`
	LastName  *string `json:"last_name,omitempty" validate:"omitempty,max=100"`
	Phone     *string `json:"phone,omitempty" validate:"omitempty,e164"`
}

// ChangePasswordRequest represents a password change request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	NewPassword     string `json:"new_password" validate:"required,min=8"`
}

// ListUsersRequest represents a request to list users
type ListUsersRequest struct {
	Page     int32  `json:"page" validate:"min=1"`
	PageSize int32  `json:"page_size" validate:"min=1,max=100"`
	Role     string `json:"role,omitempty"`
	Search   string `json:"search,omitempty"`
	SortBy   string `json:"sort_by,omitempty" validate:"omitempty,oneof=email username created_at updated_at"`
	SortDesc bool   `json:"sort_desc,omitempty"`
}

// ListUsersResponse represents the response for listing users
type ListUsersResponse struct {
	Users      []*UserProfile `json:"users"`
	Total      int64          `json:"total"`
	Page       int32          `json:"page"`
	PageSize   int32          `json:"page_size"`
	TotalPages int32          `json:"total_pages"`
}

// UserSummary represents a summary view of a user (for admin lists)
type UserSummary struct {
	ID        uuid.UUID `json:"id"`
	Email     string    `json:"email"`
	Username  string    `json:"username,omitempty"`
	FirstName string    `json:"first_name,omitempty"`
	LastName  string    `json:"last_name,omitempty"`
	Roles     []string  `json:"roles,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	Status    struct {
		Locked         bool       `json:"locked"`
		EmailVerified  bool       `json:"email_verified"`
		PhoneVerified  bool       `json:"phone_verified"`
		FailedAttempts int32      `json:"failed_attempts"`
		LastLogin      *time.Time `json:"last_login,omitempty"`
	} `json:"status"`
}
