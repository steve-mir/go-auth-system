package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
)

var (
	emailTokenLen = 42
)

// TODO: limit email sending rate per user
func SendVerificationEmail(config utils.Config, store *sqlc.Store, ctx *gin.Context, l *zap.Logger) (string, error) {
	if payload, exists := ctx.Get("authorization_payload"); exists {
		if data, ok := payload.(*token.Payload); ok {

			verifyCode, err := utils.GenerateUniqueToken(emailTokenLen)
			if err != nil {
				return "", err

			}

			link := config.AppUrl + "/verify?token=" + verifyCode
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
				Token:      verifyCode, //link,
				IsVerified: sql.NullBool{Valid: true, Bool: false},
				ExpiresAt:  time.Now().Add(time.Minute * 15),
			})
			if err != nil {
				l.Error("Error creating email verification request", zap.Error(err))
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "an unexpected error"})
				ctx.Abort()

				return "", err

			}

			return link, nil

		} else {
			l.Error("ctx data conversion error", zap.Error(errors.New("error converting ctx data to payload type")))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error getting payload from ctx"})
			ctx.Abort()
			return "", nil
		}

	} else {
		l.Error("error getting ctx", zap.Error(errors.New("error getting auth token from ctx")))
		ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error getting payload from ctx"})
		ctx.Abort()
		return "", nil
	}

}

func VerifyEmail(config utils.Config, store *sqlc.Store, link string, l *zap.Logger) error {
	// if len(link) != emailTokenLen {
	// 	l.Error("email verify error", zap.Error(errors.New("invalid token")))
	// 	return errors.New("invalid token")
	// }

	linkData, err := store.GetEmailVerificationRequestByToken(context.Background(), link)
	if err != nil {
		l.Error("error getting email token from db", zap.Error(err))
		return err
	}

	if condition := linkData.ExpiresAt.Before(time.Now()); condition {
		return fmt.Errorf("token expired")
	}

	if condition := linkData.IsVerified.Bool; condition {
		return fmt.Errorf("token already verified")
	}

	err = store.UpdateByToken(context.Background(), sqlc.UpdateByTokenParams{
		Token:      link,
		IsVerified: sql.NullBool{Bool: true, Valid: true},
	})
	if err != nil {
		l.Error("error updating token status", zap.Error(err))
		return err
	}

	err = store.UpdateUserEmailVerified(context.Background(), sqlc.UpdateUserEmailVerifiedParams{
		ID:              linkData.UserID,
		IsEmailVerified: sql.NullBool{Bool: true, Valid: true},
		EmailVerifiedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		l.Error("error updating user status", zap.Error(err))
		return err
	}

	return nil

}
