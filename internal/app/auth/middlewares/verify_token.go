package middlewares

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/app/auth/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

func Verify(config utils.Config, db *sql.DB, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {

		if payload, exists := ctx.Get(AuthorizationPayloadKey); exists {
			if data, ok := payload.(*token.Payload); ok {
				if data.RefreshID == "" {
					// Add data to error
					l.Error("wrong token error", zap.Error(errors.New("use of refresh token detected")))
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "no refresh token on payload"})
					return
					// ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
					// return
				}
				// Open a database connection
				// db, err := sql.Open(config.DBDriver, config.DBSource)
				// if err != nil {
				// 	log.Fatal("Cannot connect to db:", err)
				// }
				// defer db.Close()

				store := sqlc.NewStore(db)

				// Get the user from db
				user, err := store.GetUserByID(context.Background(), data.UserId) // ! 1
				if err != nil {
					l.Error("error fetching user by uid", zap.Error(err))
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "user not found"})
					ctx.Abort()
					return
				}

				// Check if user is deleted
				if user.IsDeleted {
					l.Error("error fetching user", zap.Error(errors.New("account deleted")))
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "account does not exists"})
					ctx.Abort()
					return

				}

				// Check if user is suspended
				if condition := user.IsSuspended.Bool; condition {
					l.Error("Error", zap.Error(errors.New("account suspended: "+user.Email)))
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "account suspended"})
					ctx.Abort()
					return

				}

				fmt.Println("REFRESH TOKEN", data.RefreshID)

				// Get the session from the db
				session, err := store.GetSessionsByID(context.Background(), data.SessionID) // ! 2
				if err != nil {
					l.Error("error fetching session by id", zap.Error(err))
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "suspicious activity detected"})
					ctx.Abort()
					return
				}

				// fmt.Println("SESSION", session)

				if session.RefreshToken != data.RefreshID && !user.IsSuspended.Bool {
					// Block user here
					fmt.Println("Illegal activity detected on " + session.ID.String())
					if err := blockUser(store, session); err != nil {
						l.Error("error blocking user", zap.Error(err))
						ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unknown error occurred. please contact support"})
						return
					}
					fmt.Println("User BLOCKED")
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "illegal activity detected, user suspended please contact support"})
					return
				}

				// Check if session is expired
				if time.Now().After(session.ExpiresAt) {
					fmt.Println("Expired: Now ", time.Now(), " Expiry ", session.ExpiresAt)
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session expired. Please login again"})
					return
				}

				// Check if session is blocked
				if session.IsBlocked {
					fmt.Println("Session ended", session.ID)
					ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "session blocked"})
					ctx.Abort()
					return
				}

				// Rotate the Refresh token
				if time.Now().After(data.Expires) {
					fmt.Println("Access token expired")
					newToken, err := generateNewAccessToken(config, store, ctx, session.ID, user)
					if err != nil {
						ctx.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to rotate refresh token"})
						return
					}

					fmt.Println("Printing new token")
					fmt.Println(newToken)
					ctx.Set(AuthorizationPayloadKey, newToken)
				}
				ctx.Next()

			} else {
				l.Error("ctx data conversion error", zap.Error(errors.New("error converting ctx data to payload type")))
				ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "payload data conversion error"})
				ctx.Abort()
				return
			}
		} else {
			l.Error("error getting ctx", zap.Error(errors.New("error getting auth token from ctx")))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "error getting payload from ctx"})
			ctx.Abort()
			return
		}

		// ctx.AbortWithStatusJSON(http.StatusUnauthorized, errors.New("session blocked"))
		// ctx.Abort()
	}

}

func blockUser(store *sqlc.Store, session sqlc.Session) error {
	log.Println("Inside block")
	// Check if

	// update isBreached = true
	err := store.UpdateSession(context.Background(), sqlc.UpdateSessionParams{ // ! 2b
		IsBreached: true,
		ID:         session.ID,
	})
	if err != nil {
		log.Fatal("Cannot update session:", err.Error())
		return err
	}

	//* update the user to isSuspended
	err = store.UpdateUserSuspension(context.Background(), sqlc.UpdateUserSuspensionParams{ // ! 2c
		ID:          session.UserID,
		IsSuspended: sql.NullBool{Bool: true, Valid: true},
		SuspendedAt: sql.NullTime{Time: time.Now(), Valid: true},
	})
	if err != nil {
		log.Println("Cannot update user:", err.Error())
		return err
	}

	// update all session with the userId (blocked to true)
	err = store.UpdateIsBlockedByUserId(context.Background(), sqlc.UpdateIsBlockedByUserIdParams{ // ! 2d
		UserID:    session.UserID,
		IsBlocked: true,
	})
	if err != nil {
		log.Println("Cannot blocked sessions:", err.Error())
		return err
	}
	log.Println("User blocked successfully.")
	return nil
}

func generateNewAccessToken(config utils.Config, store *sqlc.Store, ctx *gin.Context,
	tokenID uuid.UUID, user sqlc.User,
) (string, error) {
	clientIP := utils.GetIpAddr(ctx.ClientIP())

	// Refresh token
	refreshToken, refreshPayload, err := services.CreateUserToken(
		true, "", config, tokenID, true, user.Email, user.ID, user.IsEmailVerified.Bool,
		clientIP, ctx.Request.UserAgent(), config.RefreshTokenDuration,
	)

	if err != nil {
		log.Println("Error creating Refresh token for ", user.Email, "Error: ", err)
		return "", err
	}

	// Access token
	accessToken, _, err := services.CreateUserToken(
		false, refreshToken, config, tokenID, false, user.Email, user.ID, user.IsEmailVerified.Bool,
		clientIP, ctx.Request.UserAgent(), config.AccessTokenDuration,
	)
	if err != nil {
		log.Println("Error creating Access token for ", user.Email, "Error: ", err)
		return "", err
	}

	// println("TOKEN ID")
	// log.Println("TOKEN ID", tokenID)
	err = store.UpdateNewSession(context.Background(), sqlc.UpdateNewSessionParams{ // ! 3
		ID:           tokenID,
		RefreshToken: refreshToken,
		UserAgent:    ctx.Request.UserAgent(),
		IpAddress:    clientIP,
		ExpiresAt:    refreshPayload.Expires,
		CreatedAt: sql.NullTime{
			Time:  refreshPayload.IssuedAt,
			Valid: true,
		},
		LastActiveAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	})

	if err != nil {
		log.Println("Error updating Session for ", user.ID, "Error: ", err)
		return "", err
	}

	return accessToken, nil
}
