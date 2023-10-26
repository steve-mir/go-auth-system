package services

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

// TODO: limit email sending rate per user
func SendVerificationEmail(config utils.Config, store *sqlc.Store, ctx *gin.Context, l *zap.Logger) (string, error) {
	if payload, exists := ctx.Get("authorization_payload"); exists {
		if data, ok := payload.(*token.Payload); ok {

			verifyCode, err := utils.GenerateUniqueToken(data.UserId.String())
			if err != nil {
				return "", err

			}

			link := config.AppUrl + "/verify/" + verifyCode
			msg := "Hello " + data.Username + ", please verify your email address" + "with this link.\n" + link
			fmt.Println(msg)
			fmt.Println("Sent to ", data.Email)

			// TODO: send email here.

			//   "is_verified" boolean DEFAULT false,
			//   "created_at" timestamptz DEFAULT (now()),

			// Add link to db
			err = store.CreateEmailVerificationRequest(context.Background(), sqlc.CreateEmailVerificationRequestParams{
				UserID:     data.UserId,
				Email:      data.Email,
				Token:      link,
				IsVerified: sql.NullBool{Valid: false, Bool: false},
				ExpiresAt:  time.Now().Add(time.Minute * 15),
			})
			if err != nil {
				l.Error("Error creating email verification request", zap.Error(err))
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error getting payload from ctx"})
				ctx.Abort()

				return "", err

			}

			return link, nil

		} else {
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error getting payload from ctx"})
			ctx.Abort()
			return "", nil
		}

	} else {
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error getting payload from ctx"})
		ctx.Abort()
		return "", nil
	}

}

func VerifyEmail(config utils.Config, store *sqlc.Store, link string, l *zap.Logger) error {

	linkData, err := store.GetEmailVerificationRequestByToken(context.Background(), link)
	if err != nil {
		return err
	}

	if condition := linkData.ExpiresAt.Before(time.Now()); condition {
		return fmt.Errorf("link expired")
	}

	if condition := linkData.IsVerified.Bool; condition {
		return fmt.Errorf("link already verified")
	}

	err = store.UpdateByToken(context.Background(), sqlc.UpdateByTokenParams{
		Token:      link,
		IsVerified: sql.NullBool{Bool: true, Valid: true},
	})
	if err != nil {
		return err
	}

	err = store.UpdateUserEmailVerified(context.Background(), sqlc.UpdateUserEmailVerifiedParams{
		ID:              linkData.UserID,
		IsEmailVerified: sql.NullBool{Bool: true, Valid: true},
		VerifiedAt:      sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		return err
	}

	return nil

}
