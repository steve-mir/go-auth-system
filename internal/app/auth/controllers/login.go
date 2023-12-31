package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

type UserRequest struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8,max=64,strong_password"`
}

func Login(config utils.Config, store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		var req UserRequest
		if err := ctx.ShouldBindJSON(&req); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
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

		loginResp := services.LoginUser(config, store, ctx, l, req.Email, req.Password)
		if loginResp.Error != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": loginResp.Error.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": "User login successfully. ", "user": loginResp.User})
	}
}
