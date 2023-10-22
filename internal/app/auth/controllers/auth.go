package controllers

import (
	"database/sql"
	"log"
	"net/http"
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

type user struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=64,strong_password"`
}

func Register(config utils.Config) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req user
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate
		validate := validator.New()
		validate.RegisterValidation("strong_password", strongPasswordValidation)
		if err := validate.Struct(req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Open a database connection
		db, err := sql.Open(config.DBDriver, config.DBSource)
		if err != nil {
			log.Fatal("Cannot connect to db:", err)
		}
		defer db.Close()

		store := sqlc.NewStore(db)

		user, _, err := services.CreateUser(config, store, req.Email, req.Password)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}
		ctx.JSON(http.StatusOK, gin.H{"msg": "User registered successfully. ", "user": user})

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
