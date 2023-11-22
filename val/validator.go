package val

import (
	"fmt"
	"net/mail"
	"regexp"

	"github.com/steve-mir/go-auth-system/internal/utils"
)

var (
	isValidUsername = regexp.MustCompile(`^[a-z0-9_]+$`).MatchString
	isValidFullName = regexp.MustCompile(`^[a-zA-Z\\s]+$`).MatchString
)

func ValidateString(value string, min int, max int) error {
	if n := len(value); n < min || n > max {
		return fmt.Errorf("length must be between %d and %d characters", min, max)
	}
	return nil
}

func ValidateUsername(value string) error {
	if err := ValidateString(value, 3, 30); err != nil {
		return fmt.Errorf("invalid username: %s", err)
	}
	if !isValidUsername(value) {
		return fmt.Errorf("invalid username: %s", value)
	}
	return nil
}

func ValidateFullName(value string) error {
	if err := ValidateString(value, 3, 30); err != nil {
		return fmt.Errorf("invalid full name, length: %s", err)
	}
	if !isValidFullName(value) {
		return fmt.Errorf("invalid full name: %s", value)
	}
	return nil
}

func ValidatePassword(value string) error {

	if isStrongPwd := utils.IsStrongPasswordValidation(value); !isStrongPwd {
		return fmt.Errorf("invalid password")
	}
	return nil
}

func ValidateEmail(value string) error {
	if err := ValidateString(value, 3, 254); err != nil {
		return fmt.Errorf("invalid email length: %s", err)
	}

	if _, err := mail.ParseAddress(value); err != nil {
		return fmt.Errorf("invalid email: %s", err)
	}
	return nil
}
