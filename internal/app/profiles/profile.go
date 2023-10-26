package profiles

import "github.com/google/uuid"

type User struct {
	UserId    uuid.UUID `json:"user_id"`
	Email     string    `json:"email"`
	FirstName string    `json:"first_name"`
	LastName  string    `json:"last_name"`
	Phone     string    `json:"phone"`
	ImageUrl  string    `json:"image_url"`
}
