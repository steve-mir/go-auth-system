package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

type LoginUserResponse struct {
	SessionID             uuid.UUID `json:"session_id"`
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
	User                  sqlc.User
}

type LoginUserRequest struct {
	Email    string
	Password string
}

/**
Record failed logins and track patterns
Extract auth logic into service layer
Add OpenAPI docs for the login API
*/

// TODO: When login fails after 3 attempts, block user (to be reset through pwd reset)
func LoginUser(config utils.Config, store *sqlc.Store,
	ctx *gin.Context, l *zap.Logger, email string, pwd string,
) AuthUserResponse {
	clientIP := utils.GetIpAddr(ctx.ClientIP())

	err := HandleEmailPwdErrors(email, pwd)
	if err != nil {
		l.Error("Email password error:", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: err}
	}

	sessionID, err := uuid.NewRandom()
	if err != nil {
		l.Error("UUID error", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("an unexpected error occurred")}
	}

	//* Check login_failures for recent failures for this user from the current IP address. If too many, block login.

	user, err := store.GetUserByEmail(context.Background(), email)
	if err != nil {
		if err == sql.ErrNoRows {
			// err2 := recordFailedLogin(store, user.ID, ctx.Request.UserAgent(), clientIP)
			l.Error("Error getting email "+email, zap.Error(err))
			return AuthUserResponse{User: User{}, Error: errors.New("email or password incorrect")}
		}
		// _ = recordFailedLogin(store, user.ID, ctx.Request.UserAgent(), clientIP)
		l.Error("DB error", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("email or password incorrect")}
	}

	err = utils.CheckPassword(pwd, user.PasswordHash)
	if err != nil {
		// _ = recordFailedLogin(store, user.ID, ctx.Request.UserAgent(), clientIP)
		l.Error("wrong password", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("email or password incorrect")}
	}

	// Check if user should gain access
	err = checkAccountStat(user.IsSuspended, user.IsDeleted)
	if err != nil {
		l.Error("Checking account stat error", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: err}
	}

	// Refresh token
	refreshToken, refreshPayload, err := CreateUserToken(
		true, "", config, sessionID, true, user.Email, user.ID, user.IsEmailVerified.Bool,
		clientIP, ctx.Request.UserAgent(), config.RefreshTokenDuration,
	)

	if err != nil {
		l.Error("Error creating Refresh token for "+email, zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	// Access token
	accessToken, accessPayload, err := CreateUserToken(
		false, refreshToken, config, sessionID, false, user.Email, user.ID, user.IsEmailVerified.Bool,
		clientIP, ctx.Request.UserAgent(), config.AccessTokenDuration,
	)
	if err != nil {
		l.Error("Error creating Access token for "+email, zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	_, err = store.CreateSession(context.Background(), sqlc.CreateSessionParams{

		ID:           sessionID, //refreshPayload.ID,
		UserID:       user.ID,
		Email:        sql.NullString{String: user.Email, Valid: true},
		RefreshToken: refreshToken,
		UserAgent:    ctx.Request.UserAgent(),
		IpAddress:    clientIP,
		IsBlocked:    false,
		IsBreached:   false,
		ExpiresAt:    refreshPayload.Expires,
		CreatedAt: sql.NullTime{
			Time:  refreshPayload.IssuedAt,
			Valid: true,
		},
	})

	if err != nil {
		l.Error("Error creating Session for "+email, zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	resp := AuthUserResponse{
		User: User{
			ID:                   user.ID,
			Email:                user.Email,
			IsEmailVerified:      user.IsEmailVerified.Bool,
			CreatedAt:            user.CreatedAt.Time,
			AccessToken:          accessToken,
			AccessTokenExpiresAt: accessPayload.Expires,
			// RefreshToken:          refreshToken,
			// RefreshTokenExpiresAt: refreshPayload.Expires,
			// SessionID:             refreshPayload.ID,
		},
		Error: nil,
	}

	fmt.Println(accessToken)
	// ctx.SetCookie("accessToken", accessToken, 36000, "/", "http://localhost:9100/", false, true)

	//! 3 User logged in successfully. Record it
	err = recordLoginSuccess(store, user.ID, ctx.Request.UserAgent(), clientIP)
	if err != nil {
		l.Error("Error creating login record for "+email, zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	return resp
}

func checkAccountStat(isSuspended bool, isDeleted bool) error {
	fmt.Printf("Is Suspended %v is deleted %v", isSuspended, isDeleted)
	if isSuspended {
		log.Println("Account deleted: ", isSuspended)
		return errors.New("account suspended")
	}

	// Check if user should gain access
	if isDeleted {
		log.Println("Account deleted: ", isDeleted)
		return errors.New("account suspended")
	}
	return nil
}

func CreateUserToken(isRefreshToken bool, refreshToken string, config utils.Config, sessionID uuid.UUID,
	isRefresh bool, email string, uid uuid.UUID, IsUserVerified bool,
	ip pqtype.Inet, agent string, duration time.Duration,
) (string, *token.Payload, error) {

	maker, err := token.NewPasetoMaker(utils.GetKeyForToken(config, isRefreshToken))
	if err != nil {
		log.Println("Error creating new paseto maker for ", email, "Error: ", err)
		return "", &token.Payload{}, err
	}

	return maker.CreateToken(
		token.PayloadData{
			// Role: "user",
			RefreshID:       refreshToken,
			IsRefresh:       isRefresh,
			SessionID:       sessionID,
			UserId:          uid,
			Username:        email,
			Email:           email,
			IsEmailVerified: IsUserVerified,
			Issuer:          "Settle in",
			Audience:        "website users",
			IP:              ip,
			UserAgent:       agent,
		}, duration)
}

func recordLoginSuccess(dbStore *sqlc.Store, userId uuid.UUID, userAgent string, ipAddrs pqtype.Inet) error {
	_, err := dbStore.CreateUserLogin(context.Background(), sqlc.CreateUserLoginParams{
		UserID: userId,
		LoginAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
		UserAgent: sql.NullString{
			String: userAgent,
			Valid:  true,
		},
		IpAddress: ipAddrs,
	})
	return err
}

// When a user's login attempt fails, create a login failure entry in the login_failures table.
// This entry should include the user's ID (if available), the timestamp of the failure, IP address, and user-agent information.
// Implement logic to track login failure patterns.
// For example, if there are multiple consecutive login failures from the same IP address or for the same user,
// you may want to take additional security measures or alert the user.

/*func recordFailedLogin(dbStore *sqlc.Store, email string, userAgent string, ipAddrs pqtype.Inet) error {
	_, err := dbStore.CreateLoginFailure(context.Background(), sqlc.CreateLoginFailureParams{
		Email: email,
		Timestamp: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
		UserAgent: sql.NullString{
			String: userAgent,
			Valid:  true,
		},
		IpAddress: ipAddrs,
	})
	return err
}*/
