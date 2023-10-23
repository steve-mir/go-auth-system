package middlewares

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/token"
)

const (
	authorizationHeaderKey  = "authorization"
	authorizationTypeBearer = "bearer"
	authorizationPayloadKey = "authorization_payload"
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
func AuthMiddlerWare(tokenMaker token.Maker) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		authorizationHeader := ctx.GetHeader(authorizationHeaderKey)
		if len(authorizationHeader) == 0 {
			fmt.Println("authorization header is not provided")
			err := errors.New("authorization header is not provided")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, err) // errorResponse(err)
			return
		}

		fields := strings.Fields(authorizationHeader)
		if len(fields) < 2 {
			fmt.Println("invalid authorization header format")
			err := errors.New("invalid authorization header format")
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, err)
			return
		}

		authorizationType := strings.ToLower(fields[0])
		if authorizationType != authorizationTypeBearer {
			fmt.Printf("unsupported authorization type %s", authorizationType)
			err := fmt.Errorf("unsupported authorization type %s", authorizationType)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, err)
			return
		}

		accessToken := fields[1]
		payload, err := tokenMaker.VerifyToken(accessToken)
		if err != nil {
			// Check if token is expired then refresh
			fmt.Println("Error: ", err)
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, err.Error())
			return
		}

		// Check if email is verified

		ctx.Set(authorizationPayloadKey, payload)
		ctx.Next()
	}
}

/**
// If accessToken is deleted
func refreshAccessToken(refreshToken string) {

  // Verify refresh token
  claims, err := parseToken(refreshToken)
  //... error handling

  // Lookup user
  user := db.FindUser(claims.UserId)

  // Create new access token
  accessToken := createAccessToken(user)

  // Create new refresh token
  newRefreshToken := createRefreshToken(user)

  // Replace old refresh token with new one
  db.UpdateUserRefreshToken(user.Id, newRefreshToken)

  // Return access and refresh tokens
}
*/

/**
func AuthMiddleware(tokenMaker token.Maker, store Store) gin.HandlerFunc {

  return func(ctx *gin.Context) {

    accessToken := ctx.GetHeader("Authorization")

    // 1. Validate access token
    claims, err := tokenMaker.VerifyToken(accessToken)
    if err != nil {
      return unauthorizedError(ctx)
    }

    // 2. Lookup session
    session := store.GetSession(claims.SessionID)
    if session == nil || session.IsExpired() {
      return unauthorizedError(ctx)
    }

    // 3. Lookup user
    user, err := store.GetUser(session.UserID)
    if err != nil {
      return unauthorizedError(ctx)
    }

    // 4. Attach user to context
    ctx.Set("user", user)

    // 5. Refresh token if needed
    if session.ShouldRefresh() {
      accessToken, refreshToken := refreshTokens(session, user)
      ctx.SetCookie("refreshToken", refreshToken, maxAge, path, domain, secure, httponly)
    }

    ctx.Next()
  }

}

func refreshTokens(session sqlc.Session, user sqlc.User) {
  // issue new access & refresh tokens
  return accessToken, refreshToken
}
**/
