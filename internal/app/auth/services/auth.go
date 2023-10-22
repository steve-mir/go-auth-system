package services

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"regexp"
	"time"

	_ "github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq" // Import the PostgreSQL driver
	_ "github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"go.uber.org/zap"
)

var (
	uuidGenerator = uuid.New() // generate UUID only once
)

type user struct {
	ID                uuid.UUID `json:"id"`
	Email             string    `json:"email"`
	PasswordChangedAt time.Time `json:"password_changed_at"`
	LastLogin         time.Time `json:"last_login"`
	CreatedAt         time.Time `json:"created_at"`
	// 	SessionID             uuid.UUID `json:"session_id"`
	// 	AccessToken           string    `json:"access_token"`
	// 	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	// 	RefreshToken          string    `json:"refresh_token"`
	// 	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`

}

type RegisterUserRequest struct {
	Email    string
	Password string
}

type RegisterUserResponse struct {
	User  user
	Token string
	Error error
}

type HashResult struct {
	HashedPassword string
	Err            error
}

// func newUserResp(user sqlc.User) sqlc.User {
// 	// TODO: Still returns password = ""
// 	return sqlc.User{
// 		Email:             user.Email,
// 		ID:                user.ID,
// 		PasswordChangedAt: user.PasswordChangedAt,
// 		LastLogin:         user.LastLogin,
// 		CreatedAt:         user.CreatedAt,
// 	}
// }

// type LoginUserResponse struct {
// 	SessionID             uuid.UUID `json:"session_id"`
// 	AccessToken           string    `json:"access_token"`
// 	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
// 	RefreshToken          string    `json:"refresh_token"`
// 	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
// 	User                  sqlc.User
// }

// TODO: zap for logging
func CreateUser(config utils.Config, store *sqlc.Store, email string, pwd string) RegisterUserResponse {
	l, _ := zap.NewProduction()
	l.Info("Registeration request received for email", zap.String("email", email))

	err := handleErrors(config, store, email, pwd)
	if err != nil {
		return RegisterUserResponse{User: user{}, Token: "", Error: err}
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
		return RegisterUserResponse{User: user{}, Token: "", Error: result.Err}
	}

	// Generate UUID in advance
	uid := uuidGenerator

	params := sqlc.CreateUserParams{
		ID: uid,
		Email: sql.NullString{
			String: email,
			Valid:  true,
		},
		PasswordHash: result.HashedPassword,
		CreatedAt: sql.NullTime{
			Time:  time.Now(),
			Valid: true,
		},
	}

	// start := time.Now()
	sqlcUser, err := store.CreateUser(context.Background(), params)
	if err != nil {
		return RegisterUserResponse{User: user{}, Token: "", Error: err}
	}
	// latency := time.Since(start)

	pToken, _, err := createToken(sqlcUser, config)
	if err != nil {
		return RegisterUserResponse{User: user{}, Token: "", Error: err}
	}

	checkToken(pToken, config)

	// TODO: record metrics
	// metrics.RegisterUser()

	newUser := RegisterUserResponse{
		User: user{
			ID:                sqlcUser.ID,
			Email:             sqlcUser.Email.String,
			PasswordChangedAt: sqlcUser.CreatedAt.Time,
			LastLogin:         sqlcUser.LastLogin.Time,
			CreatedAt:         sqlcUser.CreatedAt.Time,
		},
		Token: pToken,
		Error: nil,
	}

	// logger.Info("User registered", userId)

	// metrics.RegistrationsCount.Inc()
	// metrics.RegistrationLatency.Observe(latency.Seconds())

	return newUser

}

func handleErrors(config utils.Config, store *sqlc.Store, email string, pwd string) error {
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

	// Check duplicate emails
	userEmail, _ := store.GetUserByEmail(context.Background(), sql.NullString{
		String: email,
		Valid:  true,
	})
	if userEmail.ID != uuid.Nil {
		return errors.New("user already exists")
	}

	return nil
}
func createToken(user sqlc.User, config utils.Config) (string, *token.CustomPayload, error) {
	// Create a Paseto token and include user data in the payload
	// Exclude sensitive data like the password
	maker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return "", &token.CustomPayload{}, err
	}

	// Define the payload for the token (excluding the password)
	// payload := token.Payload{
	//     // Include any user-related data you want to store in the token
	//     Username: user.Email,
	// }

	// Create the Paseto token
	pToken, payload, err := maker.CreateCustomToken(user, config.AccessTokenDuration) // Set the token expiration as needed
	return pToken, payload, err
}

/** Debug functions*/
func verifyToken(config utils.Config, pToken string) (*token.CustomPayload, error) {
	maker, err := token.NewPasetoMaker(config.TokenSymmetricKey)
	if err != nil {
		return &token.CustomPayload{}, err
	}

	payload, err2 := maker.VerifyCustomToken(pToken)

	if err2 != nil {
		return &token.CustomPayload{}, err
	}

	return payload, nil
}

func checkToken(pToken string, config utils.Config) {
	log.Println("Token", pToken)

	pUser, _ := verifyToken(config, pToken)
	log.Println(pUser.User.ID)
	log.Println(pUser.User.Email.String)
}
