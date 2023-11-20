package controllers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

func VerifyUserEmailRequest(config utils.Config, store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		link, err := services.ReSendVerificationEmail(config, store, ctx, l)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		l.Info("email verification sent", zap.String("email verification", link))
		ctx.JSON(http.StatusOK, gin.H{"msg": "Verification email sent. Please check your email"})
	}
}

func VerifyUserEmail(config utils.Config, store *sqlc.Store, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		token := ctx.Query("token")
		if token == "" {
			ctx.JSON(http.StatusBadRequest, gin.H{"error": "Token is missing"})
			return
		}
		// link := "https://www.settle-in.com/verify/bbd2518c-1d94-472c-8563-cb5ab7608bf0-1698282576-2023-10-26T02:09:36Z-KS1vLFuXAg90acMmdGvTRn77gppKcvis27jCGWcNRU="
		err := services.VerifyEmail(config, store, token, l)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": "Account verified"})
	}
}
