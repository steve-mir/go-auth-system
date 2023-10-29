package utils

import (
	"crypto/rand"
	"encoding/base64"
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

	if ip == nil {
		// Handle the case where ctx.ClientIP() doesn't return a valid IP address
		return pqtype.Inet{}
	}

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

func GetKeyForToken(config Config, isRefresh bool) string {
	var key string
	if isRefresh {
		key = config.RefreshTokenSymmetricKey
	} else {
		key = config.AccessTokenSymmetricKey
	}

	return key
}

// GenerateUniqueToken generates a unique verification token.
func GenerateUniqueToken(len int) (string, error) {
	// Generate a cryptographically secure random value
	randomBytes := make([]byte, len)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Create a unique token by combining user ID, timestamp, and random value
	// timestamp := time.Now().Unix()
	// token := fmt.Sprintf("%s-%d-%s", userID, timestamp, formatConsistentToken(timestamp, base64.URLEncoding.EncodeToString(randomBytes)))
	token := base64.URLEncoding.EncodeToString(randomBytes)

	return token, nil
}

// func formatConsistentToken(timestamp int64, randomString string) string {
// 	// Convert the timestamp to a time.Time
// 	timestampTime := time.Unix(timestamp, 0)

// 	// Format the timestamp as a string (e.g., "2023-03-06T08:46:47Z")
// 	formattedTimestamp := timestampTime.Format("2006-01-02T15:04:05Z")

// 	// Remove special characters and spaces from the random string
// 	cleanedRandomString := strings.ReplaceAll(randomString, "-", "")
// 	cleanedRandomString = strings.ReplaceAll(cleanedRandomString, "_", "")

// 	// Combine the formatted timestamp and cleaned random string
// 	consistentToken := fmt.Sprintf("%s-%s", formattedTimestamp, cleanedRandomString)

// 	return consistentToken
// }
