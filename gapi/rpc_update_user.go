package gapi

// import (
// 	"context"
// 	"database/sql"
// 	"errors"
// 	"fmt"
// 	"log"
// 	"regexp"
// 	"time"

// 	"github.com/google/uuid"
// 	"github.com/sqlc-dev/pqtype"
// 	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
// 	"github.com/steve-mir/go-auth-system/internal/token"
// 	"github.com/steve-mir/go-auth-system/internal/utils"
// 	"github.com/steve-mir/go-auth-system/pb"
// 	"github.com/steve-mir/go-auth-system/val"
// 	"go.uber.org/zap"
// 	"google.golang.org/genproto/googleapis/rpc/errdetails"
// 	"google.golang.org/grpc/codes"
// 	"google.golang.org/grpc/status"
// 	"google.golang.org/protobuf/types/known/timestamppb"
// )


// func (server *Server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
// 	// if violations := validateUpdateUserRequest(req); violations != nil {
// 	// 	return nil, invalidArgumentErr(violations)
// 	// }
// 	// TODO: Include validations

// 	agent := utils.GetUserAgent(ctx)
// 	clientIP := utils.GetIpAddr(utils.GetIP(ctx))
// 	log.Println("User ip", clientIP, " Agent", agent)

// 	server.l.Info("Update request received for email", zap.String("email", req.GetEmail()))



// 	// Hash password concurrently
// 	hashedPwdChan := make(chan HashResult)

// 	go func() {
// 		hashedPwd, err := utils.HashPassword(req.Password)
// 		result := HashResult{HashedPassword: hashedPwd, Err: err}
// 		hashedPwdChan <- result
// 	}()

// 	// To receive the result and error:
// 	result := <-hashedPwdChan

// 	if result.Err != nil {
// 		server.l.Error("Error while hashing password", zap.Error(result.Err))
// 		return nil, status.Errorf(codes.Internal, "an unexpected error occurred %s", result.Err)
// 	}


// 	params := sqlc.UpdateUserParams{
// 		// ID: req.GetId(), // TODO: Conveert to uuid
// 		Email: sql.NullString{
// 			String: req.GetEmail(),
// 			Valid:  req.Email != nil,
// 		},

// 		PasswordHash: sql.NullString{
// 			String: hashedPwd,
// 			Valid:  req.Email != nil,
// 		},
// 	}

// 	start := time.Now()

// 	tx, err := server.db.Begin()
// 	if err != nil {
// 		return nil, status.Errorf(codes.Unimplemented, "an unexpected error occurred %s", err)
// 	}
// 	defer func() {
// 		if r := recover(); r != nil {
// 			tx.Rollback()
// 		}
// 	}()

// 	qtx := server.store.WithTx(tx)

	

// 	sqlcUser, err := server.store.UpdateUser(context.Background(), params)
// 	if err != nil {
// 		server.l.Error("Error while creating user with email and password", zap.Error(err))
// 		return nil, status.Errorf(codes.Unimplemented, "error while creating user with email and password %s", err)
// 	}


	


// 	// Send verification email
// 	// TODO: services.SendVerificationEmailOnRegister(sqlcUser.ID, sqlcUser.Email, sqlcUser.Name.String, config, store, ctx, l)
// 	fmt.Println("Implement send Email")

// 	return &pb.UpdateUserResponse{
// 		User: &pb.User{
// 			FullName:  req.LastName,
// 			Username:  sqlcUser.Email,
// 			Email:     sqlcUser.Email,
// 			CreatedAt: timestamppb.New(sqlcUser.CreatedAt.Time),
// 		},
// 	}, nil

// }

// func validateUpdateUserRequest(req *pb.UpdateUserRequest) (violations []*errdetails.BadRequest_FieldViolation) {
// 	if err := val.ValidateEmail(req.GetEmail()); err != nil {
// 		violations = append(violations, fieldViolation("username", err))
// 	}

// 	if err := val.ValidatePassword(req.GetPassword()); err != nil {
// 		violations = append(violations, fieldViolation("password", err))
// 	}

// 	// TODO: Add other field validations here

// 	return violations
// }

// // ?----------------

// func HandleEmailPwdErrors(email string, pwd string) error {
// 	var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

// 	// Validate email
// 	if !emailRegex.MatchString(email) {
// 		return errors.New("wrong email format " + email)
// 	}

// 	// Validate password complexity
// 	if !utils.IsStrongPasswordValidation(pwd) {
// 		return errors.New("please use a strong password")
// 	}

// 	return nil
// }

// func checkEmailExistsError(store *sqlc.Store, email string) error {
// 	// Check duplicate emails
// 	userEmail, _ := store.GetUserByEmail(context.Background(), email)
// 	if userEmail.ID != uuid.Nil {
// 		return errors.New("user already exists")
// 	}
// 	return nil
// }

