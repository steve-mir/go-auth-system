package middlewares

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
)

var (
	AuthorizationPayloadKey = "authorization_payload"
)

/*
//*	STEPS **

	On subsequent requests:
	Validate the session token from the requests against the sessions table.
	If valid and unexpired, lookup the user_id on the session.
	Authorize the user based on user_id and session validity.

	On logout:
	Delete the session record based on token.
	Insert a record into user_logins for the logout.

	On login failure:
	Increment failure count for user from current IP.
	Insert record into login_failures table.

	Schedule job to cleanup expired sessions and old login failure records periodically.
	This allows combining the usage of all 3 tables together for a robust authentication and audit flow:
	sessions for session management
	user_logins for successful login audit trail
	login_failures for failed logins and security monitoring
*/

// ! Refresh token should be used only once. If reuse is detected end the session
// ! Create table to track access token that have been refreshed.
func AuthMiddlerWare(config utils.Config, l *zap.Logger) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authorizationHeader := ctx.GetHeader(authorizationHeaderKey)
		if len(authorizationHeader) == 0 {
			err := errors.New("authorization header is not provided")
			l.Error("auth err", zap.Error(err))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		fields := strings.Fields(authorizationHeader)
		if len(fields) < 2 {
			err := errors.New("invalid authorization header format")
			l.Error("auth err", zap.Error(err))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		authorizationType := strings.ToLower(fields[0])
		if authorizationType != authorizationTypeBearer {
			err := fmt.Errorf("unsupported authorization type %s", authorizationType)
			l.Error("auth err", zap.Error(err))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		accessToken := fields[1]

		tokenMaker, err := token.NewPasetoMaker(utils.GetKeyForToken(config, false))
		if err != nil {
			err := fmt.Errorf("could not init tokenMaker %s", err)
			l.Error("paseto maker err", zap.Error(err))
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		payload, err := tokenMaker.VerifyToken(accessToken) // Decrypts the access token and returns the data stored in it
		if err != nil {
			fmt.Println(payload)
			fmt.Println("Access Token Error: ", err)
			if err == token.ErrExpiredToken {
				fmt.Println("Token expired going to verify......")
				ctx.Set(AuthorizationPayloadKey, payload)
				return
				// ctx.Next()
			}
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		// Check if email is verified (remove if it is optional to verify email)
		// TODO: fix for 1 login or unverified emails
		// if !payload.IsUserVerified {
		// 	fmt.Println("Error: Please verify your account")
		// 	ctx.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "account not verified"})
		// 	return
		// }

		ctx.Set(AuthorizationPayloadKey, payload)
		ctx.Next()
	}
}
