package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq" // Import the PostgreSQL driver
	"github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/app/auth"

	// profiles "github.com/steve-mir/go-auth-system/internal/app/profiles/services"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

// var (
// 	uuidGenerator = uuid.New() // generate UUID only once
// )

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

type createUserResult struct {
	userResult sqlc.User
	Err        error
}

type accessTokenResult struct {
	accessToken string
	payload     *token.Payload
	err         error
}

func CreateUser(config utils.Config, ctx *gin.Context, db *sql.DB,
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
	// uid := uuidGenerator
	uid, err := uuid.NewRandom()
	if err != nil {
		l.Error("UUID error", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: errors.New("an unexpected error occurred")}
	}

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

	var newUser AuthUserResponse

	start := time.Now()

	tx, err := db.Begin()
	if err != nil {
		return AuthUserResponse{User: User{}, Error: err}
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	qtx := store.WithTx(tx)

	// TODO: Refactor and bring back go routine for createUserChan
	// createUserChan := make(chan createUserResult)
	createAccessTokenChan := make(chan accessTokenResult)
	createProfileChan := make(chan error)
	createRoleChan := make(chan error)

	// go func() {
	// 	user, err := qtx.CreateUser(context.Background(), params)
	// 	createUserChan <- createUserResult{userResult: user, Err: err}
	// }()
	sqlcUser, err := store.CreateUser(context.Background(), params)
	if err != nil {
		l.Error("Error while creating user with email and password", zap.Error(err))
		return AuthUserResponse{User: User{}, Error: err}
	}

	go func() {
		accessToken, accessPayload, err := createToken(false, "register access token", req.Email,
			false,
			uid, clientIP, ctx.Request.UserAgent(), config)
		createAccessTokenChan <- accessTokenResult{accessToken: accessToken, payload: accessPayload, err: err}
	}()

	go func() {
		profileErr := qtx.CreateUserProfile(context.Background(), sqlc.CreateUserProfileParams{
			UserID:    uid,
			FirstName: sql.NullString{String: req.FirstName, Valid: true},
			LastName:  sql.NullString{String: req.LastName, Valid: true},
		})
		createProfileChan <- profileErr
	}()

	go func() {
		_, roleErr := qtx.CreateUserRole(context.Background(), sqlc.CreateUserRoleParams{
			UserID: uid,
			RoleID: 1,
		})
		createRoleChan <- roleErr
	}()

	// sqlcUser := <-createUserChan
	// if sqlcUser.Err != nil {
	// 	l.Error("Error while creating user", zap.Error(sqlcUser.Err))
	// 	tx.Rollback()
	// 	return AuthUserResponse{User: User{}, Error: sqlcUser.Err}
	// }

	claims := <-createAccessTokenChan
	if claims.err != nil {
		l.Error("Error creating access token", zap.Error(claims.err))
		tx.Rollback()
		return AuthUserResponse{User: User{}, Error: claims.err}
	}

	if <-createProfileChan != nil {
		l.Error("Error creating User profile", zap.Error(<-createProfileChan))
		tx.Rollback()
		return AuthUserResponse{User: User{}, Error: <-createProfileChan}
	}

	if <-createRoleChan != nil {
		l.Error("Error creating User role", zap.Error(<-createRoleChan))
		tx.Rollback()
		return AuthUserResponse{User: User{}, Error: <-createRoleChan}
	}

	newUser = AuthUserResponse{
		User: User{
			ID:                   sqlcUser.ID,
			Email:                sqlcUser.Email,
			IsEmailVerified:      sqlcUser.IsEmailVerified.Bool,
			PasswordChangedAt:    sqlcUser.CreatedAt.Time,
			CreatedAt:            sqlcUser.CreatedAt.Time,
			AccessToken:          claims.accessToken,
			AccessTokenExpiresAt: claims.payload.Expires,
		},
		Error: tx.Commit(),
	}

	latency := time.Since(start)
	fmt.Println("Create user Account time ", latency)

	// Send verification email
	SendVerificationEmailOnRegister(sqlcUser.ID, sqlcUser.Email, sqlcUser.Name.String, config, store, ctx, l)
	fmt.Println("Email sent")
	return newUser

	/*start := time.Now()
	err = store.ExecTx(context.Background(), func(q *sqlc.Queries) error {
		sqlcUser, err := store.CreateUser(context.Background(), params)
		if err != nil {
			l.Error("Error while creating user with email and password", zap.Error(err))
			return err
		}

		accessToken, accessPayload, err := createToken(false, "register access token", sqlcUser.Email,
			false, // sqlcUser.IsEmailVerified.Bool,
			sqlcUser.ID, clientIP, ctx.Request.UserAgent(), config)
		if err != nil {
			l.Error("Error creating access token", zap.Error(err))
			return err
		}

		// Create user profile
		err = profiles.CreateUserProfile(store, auth.UserAuth{
			UserId:    sqlcUser.ID,
			FirstName: req.FirstName,
			LastName:  req.LastName,
		})
		if err != nil {
			l.Error("Error creating User profile", zap.Error(err))
			return err
		}

		_, err = store.CreateUserRole(context.Background(), sqlc.CreateUserRoleParams{
			UserID: sqlcUser.ID,
			RoleID: 1,
		})
		if err != nil {
			l.Error("Error creating User role", zap.Error(err))
			return err
		}

		newUser = AuthUserResponse{
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
		return nil
	})
	latency := time.Since(start)
	fmt.Println("Create user Account time ", latency)*/

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
