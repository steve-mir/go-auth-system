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
// TODO: Implement throttling to prevent brute force attacks
*/

/**
Record failed logins and track patterns
Extract auth logic into service layer
Add OpenAPI docs for the login API
*/

func LoginUser(config utils.Config, store *sqlc.Store, ctx *gin.Context, email string, pwd string) AuthUserResponse {
	clientIP := utils.GetIpAddr(ctx.ClientIP())

	err := HandleEmailPwdErrors(email, pwd)
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}

	tokenID, err := uuid.NewRandom()
	if err != nil {
		// log error
		return AuthUserResponse{User: User{}, Error: errors.New("an unexpected error occurred")}
	}
	// l, _ := zap.NewProduction()

	//* Check login_failures for recent failures for this user from the current IP address. If too many, block login.

	user, err := store.GetUserByEmail(context.Background(), sql.NullString{String: email, Valid: true})
	if err != nil {
		if err == sql.ErrNoRows {
			// err2 := recordFailedLogin(store, user.ID, ctx.Request.UserAgent(), clientIP)
			fmt.Println("User not found: ", email, err)
			// l.Error("User not found", zap.String("email", email))
			return AuthUserResponse{User: User{}, Error: errors.New("email or password incorrect")}
		}
		// _ = recordFailedLogin(store, user.ID, ctx.Request.UserAgent(), clientIP)
		fmt.Println("DB error: ", err)
		// l.Error("DB error", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("email or password incorrect")}
	}

	err = utils.CheckPassword(pwd, user.PasswordHash)
	if err != nil {
		// _ = recordFailedLogin(store, user.ID, ctx.Request.UserAgent(), clientIP)
		fmt.Println("Hashing error: ", err)
		// l.Error("wrong email or password", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("email or password incorrect")}
	}

	// Access token
	accessToken, accessPayload, err := createUserToken(
		config, tokenID, "accessToken", user.Email.String, user.ID, user.IsVerified.Bool,
		clientIP, ctx.Request.UserAgent(), config.AccessTokenDuration,
	)
	if err != nil {
		log.Println("Error creating Access token for ", email, "Error: ", err)
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	// Refresh token
	refreshToken, refreshPayload, err := createUserToken(
		config, tokenID, "refreshToken", user.Email.String, user.ID, user.IsVerified.Bool,
		clientIP, ctx.Request.UserAgent(), config.RefreshTokenDuration,
	)

	if err != nil {
		log.Println("Error creating Refresh token for ", email, "Error: ", err)
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	_, err = store.CreateSession(context.Background(), sqlc.CreateSessionParams{

		ID:           tokenID, //refreshPayload.ID,
		UserID:       user.ID,
		Email:        user.Email,
		RefreshToken: refreshToken,
		UserAgent:    ctx.Request.UserAgent(),
		IpAddress:    clientIP,
		IsBlocked:    false,
		ExpiresAt:    refreshPayload.Expires,
		CreatedAt: sql.NullTime{
			Time:  refreshPayload.IssuedAt,
			Valid: true,
		},
	})

	if err != nil {
		log.Println("Error creating Session for ", email, "Error: ", err)
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	resp := AuthUserResponse{
		User: User{
			ID:                    user.ID,
			Email:                 user.Email.String,
			IsEmailVerified:       user.IsVerified.Bool,
			LastLogin:             user.LastLogin.Time,
			CreatedAt:             user.CreatedAt.Time,
			AccessToken:           accessToken,
			AccessTokenExpiresAt:  accessPayload.Expires,
			RefreshToken:          refreshToken,
			RefreshTokenExpiresAt: refreshPayload.Expires,
			// SessionID:             refreshPayload.ID,
		},
		Error: nil,
	}

	maker, _ := token.NewPasetoMaker(config.TokenSymmetricKey)
	fmt.Println(accessToken)
	cPayload, err := maker.VerifyToken(accessToken)
	if err != nil {
		return AuthUserResponse{User: User{}, Error: errors.New("paseto token verification failed")}
	}

	// TODO: Use to test verify. Remove after
	rPayload, err := maker.VerifyToken(refreshToken)
	if err != nil {
		return AuthUserResponse{User: User{}, Error: errors.New("paseto token verification failed")}
	}

	log.Println("Printing user from Access token")
	fmt.Printf("%+v\n", cPayload)
	log.Println("Printing user from Refresh token")
	fmt.Printf("%+v\n", rPayload)

	//! 3 User logged in successfully. Record it
	err = recordLoginSuccess(store, user.ID, ctx.Request.UserAgent(), clientIP)
	if err != nil {
		log.Println("Error creating login record for ", email, "Error: ", err)
		return AuthUserResponse{User: User{}, Error: errors.New("an unknown error occurred")}
	}

	return resp
}

func createUserToken(config utils.Config, tokenID uuid.UUID, tokenType string,
	email string, uid uuid.UUID, IsUserVerified bool, ip pqtype.Inet,
	agent string, duration time.Duration,
) (string, *token.Payload, error) {

	maker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		log.Println("Error creating new paseto maker for ", email, "Error: ", err)
		return "", &token.Payload{}, err
	}

	return maker.CreateToken(
		token.PayloadData{
			SessionID:      tokenID,
			Type:           tokenType,
			UserId:         uid,
			Username:       email,
			IsUserVerified: IsUserVerified,
			// Role: "user",
			Issuer:    "Settle in",
			Audience:  "website users",
			IP:        ip,
			UserAgent: agent,
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