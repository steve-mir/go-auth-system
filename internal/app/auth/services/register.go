package services

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq" // Import the PostgreSQL driver
	"github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/app/auth"
	profiles "github.com/steve-mir/go-auth-system/internal/app/profiles/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

var (
	uuidGenerator = uuid.New() // generate UUID only once
)

type User struct {
	ID                   uuid.UUID `json:"id"`
	Email                string    `json:"email"`
	IsEmailVerified      bool      `json:"is_email_verified"`
	PasswordChangedAt    time.Time `json:"password_changed_at"`
	LastLogin            time.Time `json:"last_login"`
	CreatedAt            time.Time `json:"created_at"`
	SessionID            uuid.UUID `json:"session_id"`
	AccessToken          string    `json:"access_token"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`
	// RefreshToken          string    `json:"refresh_token"`
	// RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
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

func CreateUser(config utils.Config, ctx *gin.Context,
	store *sqlc.Store, l *zap.Logger, req auth.UserAuth,
) AuthUserResponse {
	clientIP := utils.GetIpAddr(ctx.ClientIP())
	l.Info("Registration request received for email", zap.String("email", req.Email))

	err := HandleEmailPwdErrors(req.Email, req.Password)
	if err != nil {
		l.Error("Email password error", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: err}
	}

	err = checkEmailExistsError(store, req.Email)
	if err != nil {
		l.Error("Error while fetching email from db", zap.Error(err))
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
		hashedPwd, err := utils.HashPassword(req.Password)
		result := HashResult{HashedPassword: hashedPwd, Err: err}
		hashedPwdChan <- result
	}()

	// To receive the result and error:
	result := <-hashedPwdChan

	if result.Err != nil {
		l.Error("Error while hashing password", zap.Error(result.Err))
		return AuthUserResponse{User: User{}, Error: result.Err}
	}

	// Generate UUID in advance
	uid := uuidGenerator

	params := sqlc.CreateUserParams{
		ID:    uid,
		Email: req.Email, IsVerified: sql.NullBool{Bool: true, Valid: true},
		PasswordHash: result.HashedPassword,
		CreatedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
		IsSuspended: false,
		IsDeleted:   false,
	}

	// start := time.Now()
	sqlcUser, err := store.CreateUser(context.Background(), params)
	if err != nil {
		l.Error("Error while creating user with email and password", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: err}
	}
	// latency := time.Since(start)

	accessToken, accessPayload, err := createToken(false, "register access token", sqlcUser.Email,
		false, // sqlcUser.IsEmailVerified.Bool,
		sqlcUser.ID, clientIP, ctx.Request.UserAgent(), config)
	if err != nil {
		l.Error("Error creating access token", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: err}
	}

	// Optional Create session for user when they register

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
	err = profiles.CreateUserProfile(config, store, ctx, l, auth.UserAuth{
		UserId:    sqlcUser.ID,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	})
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}

	return newUser

}

func HandleEmailPwdErrors(email string, pwd string) error {
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
func createToken(isRefreshToken bool, refreshToken string, email string, isEmailVerified bool,
	userId uuid.UUID, ip pqtype.Inet, userAgent string, config utils.Config,
) (string, *token.Payload, error) {

	// Create a Paseto token and include user data in the payload
	maker, err := token.NewPasetoMaker(utils.GetKeyForToken(config, isRefreshToken))
	if err != nil {
		return "", &token.Payload{}, err
	}

	// Define the payload for the token (excluding the password)
	payloadData := token.PayloadData{
		RefreshID:       refreshToken,
		IsRefresh:       false,
		UserId:          userId,
		Username:        email,
		Email:           email,
		IsEmailVerified: isEmailVerified,
		Issuer:          "Settle in",
		Audience:        "website users",
		IP:              ip,
		UserAgent:       userAgent,
		// Role: "user",
		// SessionID uuid.UUID `json:"session_id"`
	}

	// Create the Paseto token
	pToken, payload, err := maker.CreateToken(payloadData, config.AccessTokenDuration) // Set the token expiration as needed
	return pToken, payload, err
}
