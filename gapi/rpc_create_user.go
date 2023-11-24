package gapi

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
	"github.com/sqlc-dev/pqtype"
	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/token"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/steve-mir/go-auth-system/pb"
	"github.com/steve-mir/go-auth-system/val"
	"github.com/steve-mir/go-auth-system/worker"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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

type accessTokenResult struct {
	accessToken string
	payload     *token.Payload
	err         error
}

func (server *Server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	if violations := validateCreateUserRequest(req); violations != nil {
		return nil, invalidArgumentErr(violations)
	}

	agent := server.extractMetadata(ctx).UserAgent
	ip := server.extractMetadata(ctx).ClientIP

	clientIP := utils.GetIpAddr(ip)
	log.Println("User ip", clientIP, " Agent", agent)

	server.l.Info("Registration request received for email", zap.String("email", req.GetEmail()))

	err := HandleEmailPwdErrors(req.GetEmail(), req.GetPassword())
	if err != nil {
		// server.l.Error("Email password error", zap.Error(err))
		log.Printf("Email password error %s", err)
		return nil, status.Errorf(codes.Internal, "email password error: %s", err)
	}

	err = checkEmailExistsError(server.store, req.Email)
	if err != nil {
		server.l.Error("Error while fetching email from db", zap.Error(err))
		return nil, status.Errorf(codes.AlreadyExists, "error while fetching email from db: %s", err)

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
		server.l.Error("Error while hashing password", zap.Error(result.Err))
		return nil, status.Errorf(codes.Internal, "an unexpected error occurred %s", result.Err)
	}

	// Generate UUID in advance
	// uid := uuidGenerator
	uid, err := uuid.NewRandom()
	if err != nil {
		server.l.Error("UUID error", zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "an unexpected error occurred %s", err)
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

	start := time.Now()

	tx, err := server.db.Begin()
	if err != nil {
		return nil, status.Errorf(codes.Unimplemented, "an unexpected error occurred %s", err)
	}
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	qtx := server.store.WithTx(tx)

	createAccessTokenChan := make(chan accessTokenResult)
	createProfileChan := make(chan error)
	createRoleChan := make(chan error)

	sqlcUser, err := server.store.CreateUser(context.Background(), params)
	if err != nil {
		server.l.Error("Error while creating user with email and password", zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "error while creating user with email and password %s", err)
	}

	go func() {
		accessToken, accessPayload, err := createToken(false, "register access token", req.Email,
			false,
			uid, clientIP, agent, server.config)
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

	claims := <-createAccessTokenChan
	if claims.err != nil {
		server.l.Error("Error creating access token", zap.Error(claims.err))
		tx.Rollback()
		return nil, status.Errorf(codes.Unimplemented, "Error creating access token %s", claims.err)
	}

	if <-createProfileChan != nil {
		server.l.Error("Error creating User profile", zap.Error(<-createProfileChan))
		tx.Rollback()
		return nil, status.Errorf(codes.Unimplemented, "Error creating User profile %s", <-createProfileChan)
	}

	if <-createRoleChan != nil {
		server.l.Error("Error creating User role", zap.Error(<-createRoleChan))
		tx.Rollback()
		return nil, status.Errorf(codes.Internal, "error creating User role %s", <-createRoleChan)
	}

	latency := time.Since(start)
	fmt.Println("Create user Account time ", latency)

	//TODO:  Add to transaction. If process fails, do not run
	// *****************************************/
	// Send verification email
	taskPayload := &worker.PayloadSendVerifyEmail{
		Username: sqlcUser.Email,
	}

	opts := []asynq.Option{
		asynq.MaxRetry(10),
		asynq.ProcessIn(10 * time.Second),
		asynq.Queue(worker.QueueCritical),
	}

	err = server.taskDistributor.DistributeTaskSendVerifyEmail(ctx, taskPayload, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to distribute task to send verify email %s", err)
	}
	// *****************************************/
	fmt.Println("Implement send Email")

	return &pb.CreateUserResponse{
		User: &pb.User{
			Uid:             uid.String(),
			IsEmailVerified: sqlcUser.IsEmailVerified.Bool,
			IsVerified:      sqlcUser.IsVerified.Bool,
			IsDeleted:       sqlcUser.IsDeleted,
			FullName:        req.LastName,
			Username:        sqlcUser.Email,
			Email:           sqlcUser.Email,
			CreatedAt:       timestamppb.New(sqlcUser.CreatedAt.Time),
		},
	}, tx.Commit()

}

func validateCreateUserRequest(req *pb.CreateUserRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if err := val.ValidateEmail(req.GetEmail()); err != nil {
		violations = append(violations, fieldViolation("username", err))
	}

	if err := val.ValidatePassword(req.GetPassword()); err != nil {
		violations = append(violations, fieldViolation("password", err))
	}

	// TODO: Add other field validations here

	return violations
}

// ?----------------

func HandleEmailPwdErrors(email string, pwd string) error {
	var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

	// Validate email
	if !emailRegex.MatchString(email) {
		return errors.New("wrong email format " + email)
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
