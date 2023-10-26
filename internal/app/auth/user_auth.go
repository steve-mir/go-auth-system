package auth

import (
	"github.com/google/uuid"
)

type UserAuth struct {
	UserId    uuid.UUID `json:"user_id"`
	Email     string    `json:"email" validate:"required,email"`
	Password  string    `json:"password" validate:"required,min=8,max=64,strong_password"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Phone     string    `json:"phone"`
	ImageUrl  string    `json:"image_url"`
}
