package config

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/steve-mir/go-auth-system/internal/errors"
)

// getEnvString returns the value of an environment variable or the default value
func getEnvString(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt returns the integer value of an environment variable or the default value
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvBool returns the boolean value of an environment variable or the default value
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		switch strings.ToLower(value) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off":
			return false
		}
	}
	return defaultValue
}

// getEnvDuration returns the duration value of an environment variable or the default value
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// getEnvStringSlice returns a string slice from a comma-separated environment variable
func getEnvStringSlice(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(value, ",")
	}
	return defaultValue
}

// validateRequired checks if required environment variables are set
func validateRequired(vars ...string) error {
	for _, v := range vars {
		if os.Getenv(v) == "" {
			return errors.New(errors.ErrorTypeValidation, "MISSING_ENV_VAR", "required environment variable is not set: "+v)
		}
	}
	return nil
}
