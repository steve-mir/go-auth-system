package security

type PwdResetRequest struct {
	Email string `json:"email" validate:"required,email"`
}

type NewPwdRequest struct {
	Password  string `json:"password" validate:"required"`
	Password2 string `json:"password2" validate:"required"`
}
