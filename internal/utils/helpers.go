package utils

import (
	"net"
	"regexp"

	"github.com/sqlc-dev/pqtype"
)

// getIpAddr returns a pqtype.Inet representation of the client's IP address.
//
// It takes a string parameter, clientIP, which represents the client's IP address.
// It returns a pqtype.Inet value.
func GetIpAddr(clientIP string) pqtype.Inet {
	ip := net.ParseIP(clientIP)

	// if ip == nil {
	// 	 TODO: Handle the case where ctx.ClientIP() doesn't return a valid IP address
	// }

	inet := pqtype.Inet{
		IPNet: net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32), // If you're dealing with IPv4 addresses
		},
		Valid: true,
	}
	return inet
}

func IsStrongPasswordValidation(password string) bool {

	// Check if the password is greater than 8 characters
	if len(password) <= 8 {
		return false
	}

	// Check if the password is less than 64 characters
	if len(password) >= 64 {
		return false
	}

	// Add additional rules for a strong password
	// Example: At least one uppercase letter, one lowercase letter, one digit, and one special character

	// Check for complexity
	hasUppercase := regexp.MustCompile(`[A-Z]`).MatchString(password)
	hasLowercase := regexp.MustCompile(`[a-z]`).MatchString(password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecialChar := regexp.MustCompile(`[!@#$%^&*()]`).MatchString(password)

	if !hasUppercase || !hasLowercase || !hasNumber || !hasSpecialChar {
		return false
	}

	// Check for common patterns
	commonPatterns := []string{"123456", "password"} // Add more common patterns if needed
	for _, pattern := range commonPatterns {
		if password == pattern {
			return false
		}
	}

	// Check for uniqueness
	// You can add your own logic here to check if the password has been used before

	// Check for personal information
	// You can add your own logic here to check if the password contains personal information

	// Check for randomness
	// You can add your own logic here to check if the password is random

	return true
}
