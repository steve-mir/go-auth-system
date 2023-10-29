package security

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator"

	security "github.com/steve-mir/go-auth-system/internal/app/security"
	services "github.com/steve-mir/go-auth-system/internal/app/security/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

// type PwdResetRequest struct {
// 	Email string `json:"email" validate:"required,email"`
// }

// type NewPwdRequest struct {
// 	Password  string `json:"password" validate:"required"`
// 	Password2 string `json:"password2" validate:"required"`
// }

func ResetUserPwdRequest(config utils.Config, store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req security.PwdResetRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate
		validate := validator.New()
		if err := validate.Struct(req); err != nil {
			l.Error("Go validator error", zap.Error(err))
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		res, err := services.SendPasswordResetEmail(config, store, ctx, l, req.Email)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": res})
	}
}

func ResetPwd(config utils.Config, store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req security.NewPwdRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		token := ctx.Query("token")
		if token == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Token is missing"})
			return
		}

		// Validate
		validate := validator.New()
		if err := validate.Struct(req); err != nil {
			l.Error("Go validator error", zap.Error(err))
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate password input
		if err := handlePwdErrors(req); err != nil {
			l.Error("Input error", zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if err := services.ResetPassword(config, store, token, l, req); err != nil {
			l.Error("Reset pwd error", zap.Error(err))
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": "Password successfully changed"})
	}
}

func handlePwdErrors(pwd security.NewPwdRequest) error {
	if pwd.Password != pwd.Password2 {
		return errors.New("both passwords must be equal")
	}

	// Validate password complexity
	if !utils.IsStrongPasswordValidation(pwd.Password) {
		return errors.New("please use a strong password")
	}

	return nil
}
