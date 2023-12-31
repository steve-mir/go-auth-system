package controllers

import (
	"database/sql"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/steve-mir/go-auth-system/internal/app/auth"
	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

func Register(config utils.Config, db *sql.DB, store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req auth.UserAuth
		if err := ctx.ShouldBindJSON(&req); err != nil {
			l.Error("Invalid fields error", zap.Error(err))
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "email and password fields required", "status": err.Error()})
			return
		}

		// Validate
		validate := validator.New()
		validate.RegisterValidation("strong_password", strongPasswordValidation)
		if err := validate.Struct(req); err != nil {
			l.Error("Go validator error", zap.Error(err))
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		newUserResp := services.CreateUser(config, ctx, db, store, l, req)
		if newUserResp.Error != nil {
			l.Error("Create User error", zap.Error(newUserResp.Error))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": newUserResp.Error.Error()})
			return
		}

		// Record logs/metrics
		l.Info("User registered", zap.Any("uid", newUserResp.User.ID))
		// metrics.Registrations.Inc()
		ctx.JSON(http.StatusOK, gin.H{"msg": "User registered successfully. ", "user": newUserResp.User})

	}
}

func strongPasswordValidation(fl validator.FieldLevel) bool {
	password := fl.Field().String()

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
