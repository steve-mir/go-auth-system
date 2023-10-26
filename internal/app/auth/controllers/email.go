package controllers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

func VerifyUserEmailRequest(config utils.Config, db *sql.DB, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		store := sqlc.NewStore(db)

		link, err := services.SendVerificationEmail(config, store, ctx, l)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": "Verification email sent. Please check your email", "link": link})
	}
}

func VerifyUserEmail(config utils.Config, db *sql.DB, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		store := sqlc.NewStore(db)

		link := "https://www.settle-in.com/verify/bbd2518c-1d94-472c-8563-cb5ab7608bf0-1698282576-2023-10-26T02:09:36Z-KS1vLFuXAg90acMmdGvTRn77gppKcvis27jCGWcNRU="
		err := services.VerifyEmail(config, store, link, l)
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		ctx.JSON(http.StatusOK, gin.H{"msg": "Account verified"})
	}
}
