package utils

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword generates a hashed version of the provided password using bcrypt algorithm.
// It returns the hashed password as a string.
func HashPassword(pwd string) (string, error) {
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashPassword), nil
}

// CheckPassword compares a plain-text password with a hashed password.
//
// It takes in two parameters:
// - `pwd` (string): The plain-text password to be checked.
// - `hashedPwd` (string): The hashed password to compare against.
//
// It returns an error if the comparison fails.
func CheckPassword(pwd string, hashedPwd string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPwd), []byte(pwd))
}
