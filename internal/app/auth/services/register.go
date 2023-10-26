package services

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq" // Import the PostgreSQL driver
	"github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

var (
	uuidGenerator = uuid.New() // generate UUID only once
)

type User struct {
	ID                    uuid.UUID `json:"id"`
	Email                 string    `json:"email"`
	IsEmailVerified       bool      `json:"is_email_verified"`
	PasswordChangedAt     time.Time `json:"password_changed_at"`
	LastLogin             time.Time `json:"last_login"`
	CreatedAt             time.Time `json:"created_at"`
	SessionID             uuid.UUID `json:"session_id"`
	AccessToken           string    `json:"access_token"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshToken          string    `json:"refresh_token"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}

type RegisterUserRequest struct {
	Email    string
	Password string
}

type AuthUserResponse struct {
	User  User
	Error error
}

type HashResult struct {
	HashedPassword string
	Err            error
}

// *671#

// TODO: zap for logging
func CreateUser(config utils.Config, ctx *gin.Context, store *sqlc.Store, email string, pwd string) AuthUserResponse {
	clientIP := utils.GetIpAddr(ctx.ClientIP())
	l, _ := zap.NewProduction()
	l.Info("Registeration request received for email", zap.String("email", email))

	err := HandleEmailPwdErrors(email, pwd)
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}

	err = checkEmailExistsError(store, email)
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}

	// start db txn

	// if dupUser := checkDuplicateEmail(req.Email); dupUser != nil {
	// 	// return error
	// }

	// generate UUID
	// hash password
	// create user
	// commit txn

	// Hash password concurrently
	hashedPwdChan := make(chan HashResult)
	go func() {
		hashedPwd, err := utils.HashPassword(pwd)
		result := HashResult{HashedPassword: hashedPwd, Err: err}
		hashedPwdChan <- result
	}()

	// To receive the result and error:
	result := <-hashedPwdChan

	if result.Err != nil {
		return AuthUserResponse{User: User{}, Error: result.Err}
	}

	// Generate UUID in advance
	uid := uuidGenerator

	params := sqlc.CreateUserParams{
		ID:    uid,
		Email: email, IsVerified: sql.NullBool{Bool: true, Valid: true},
		PasswordHash: result.HashedPassword,
		CreatedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}

	// start := time.Now()
	sqlcUser, err := store.CreateUser(context.Background(), params)
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}
	// latency := time.Since(start)

	// Refresh token
	// refreshToken, refreshPayload, err := createToken(false, sqlcUser.Email, sqlcUser.ID, clientIP, ctx.Request.UserAgent(), config)
	// if err != nil {
	// 	return AuthUserResponse{User: User{}, Error: err}
	// }

	refreshToken := "new user"
	accessToken, accessPayload, err := createToken(false, refreshToken, sqlcUser.Email, sqlcUser.ID, clientIP, ctx.Request.UserAgent(), config)
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}

	// TODO: Create session for user when they register

	checkToken(false, accessToken, config)

	// TODO: record metrics
	// metrics.RegisterUser()

	newUser := AuthUserResponse{
		User: User{
			ID:                   sqlcUser.ID,
			Email:                sqlcUser.Email,
			IsEmailVerified:      sqlcUser.IsEmailVerified.Bool,
			PasswordChangedAt:    sqlcUser.CreatedAt.Time,
			CreatedAt:            sqlcUser.CreatedAt.Time,
			AccessToken:          accessToken,
			AccessTokenExpiresAt: accessPayload.Expires,
		},
		Error: nil,
	}

	// logger.Info("User registered", userId)

	// metrics.RegistrationsCount.Inc()
	// metrics.RegistrationLatency.Observe(latency.Seconds())

	// TODO: Create user profile

	return newUser

}

func HandleEmailPwdErrors(email string, pwd string) error {
	// var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")
	var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	// Validate email
	if !emailRegex.MatchString(email) {
		return errors.New("wrong email format")
	}

	// Validate password complexity
	if !utils.IsStrongPasswordValidation(pwd) {
		return errors.New("please use a strong password")
	}

	return nil
}

func checkEmailExistsError(store *sqlc.Store, email string) error {
	// Check duplicate emails
	userEmail, _ := store.GetUserByEmail(context.Background(), email)
	if userEmail.ID != uuid.Nil {
		return errors.New("user already exists")
	}
	return nil
}
func createToken(isRefreshToken bool, refreshToken string, email string, userId uuid.UUID, ip pqtype.Inet, userAgent string, config utils.Config) (string, *token.Payload, error) {
	// Create a Paseto token and include user data in the payload
	// todo: Exclude sensitive data like the password
	maker, err := token.NewPasetoMaker(utils.GetKeyForToken(config, isRefreshToken))
	if err != nil {
		return "", &token.Payload{}, err
	}

	// Define the payload for the token (excluding the password)
	payloadData := token.PayloadData{
		RefreshID: refreshToken,
		IsRefresh: false,
		UserId:    userId,
		Username:  email,
		Email:     email,
		Issuer:    "Settle in",
		Audience:  "website users",
		IP:        ip,
		UserAgent: userAgent,
		// Role: "user",
		// SessionID uuid.UUID `json:"session_id"`
	}

	// Create the Paseto token
	pToken, payload, err := maker.CreateToken(payloadData, config.AccessTokenDuration) // Set the token expiration as needed
	return pToken, payload, err
}

/** Debug functions*/
func verifyToken(isRefreshToken bool, config utils.Config, pToken string) (*token.Payload, error) {
	maker, err := token.NewPasetoMaker(utils.GetKeyForToken(config, isRefreshToken))
	if err != nil {
		return &token.Payload{}, err
	}

	payload, err2 := maker.VerifyToken(pToken)

	if err2 != nil {
		return &token.Payload{}, err
	}

	return payload, nil
}

func checkToken(isRefreshToken bool, pToken string, config utils.Config) {
	log.Println("Token", pToken)

	pUser, _ := verifyToken(isRefreshToken, config, pToken)
	log.Println(pUser.UserId)
	log.Println(pUser.Username)
}
