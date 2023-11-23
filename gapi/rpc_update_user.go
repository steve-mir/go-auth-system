package gapi

import (
	"context"
	"database/sql"
	"log"

	"github.com/steve-mir/go-auth-system/internal/db/sqlc"
	"github.com/steve-mir/go-auth-system/internal/utils"
	"github.com/steve-mir/go-auth-system/pb"
	"github.com/steve-mir/go-auth-system/val"
	"go.uber.org/zap"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (server *Server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	authPayload, err := server.authorizeUser(ctx)
	if err != nil {
		return nil, unauthenticatedError(err)
	}

	if violations := validateUpdateUserRequest(req); violations != nil {
		return nil, invalidArgumentErr(violations)
	}

	// agent := server.extractMetadata(ctx).UserAgent
	// ip := server.extractMetadata(ctx).ClientIP

	// clientIP := utils.GetIpAddr(ip)
	// log.Println("User ip", clientIP, " Agent", agent)

	// if authPayload.Email != req.GetEmail() {
	// 	return nil, status.Errorf(codes.PermissionDenied, "cannot update another user's data")
	// }
	log.Println("User", authPayload.Email)

	server.l.Info("Update request received for email", zap.String("email", req.GetEmail()))

	params := sqlc.UpdateUserParams{
		// ID: req.GetId(), // TODO: Convert to uuid. Get id from ctx
		Email: sql.NullString{
			String: req.GetEmail(),
			Valid:  req.Email != nil,
		},

		ID: authPayload.UserId,

		Username: sql.NullString{
			String: req.GetUsername(),
			Valid:  req.Username != nil,
		},
	}

	// If user is updating password
	if req.Password != nil {
		// Hash password concurrently
		hashedPwdChan := make(chan HashResult)

		go func() {
			hashedPwd, err := utils.HashPassword(req.GetPassword())
			result := HashResult{HashedPassword: hashedPwd, Err: err}
			hashedPwdChan <- result
		}()

		// To receive the result and error:
		result := <-hashedPwdChan

		if result.Err != nil {
			server.l.Error("Error while hashing password", zap.Error(result.Err))
			return nil, status.Errorf(codes.Internal, "an unexpected error occurred %s", result.Err)
		}

		params.PasswordHash = sql.NullString{
			String: result.HashedPassword,
			Valid:  true,
		}
	}

	// TODO: Add other fields that need updating

	// Update data
	user, err := server.store.UpdateUser(ctx, params)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		server.l.Error("Error while creating user with email and password", zap.Error(err))
		return nil, status.Errorf(codes.Unimplemented, "error while creating user with email and password %s", err)
	}

	return &pb.UpdateUserResponse{
		User: &pb.User{
			FullName: user.Name.String,
			Username: user.Email,
			Email:    user.Email,
			// CreatedAt: timestamppb.New(sqlcUser.CreatedAt.Time),
		},
	}, nil

}

// Validate inputs
func validateUpdateUserRequest(req *pb.UpdateUserRequest) (violations []*errdetails.BadRequest_FieldViolation) {
	if req.Email != nil {
		if err := val.ValidateEmail(req.GetEmail()); err != nil {
			violations = append(violations, fieldViolation("username", err))
		}
	}

	if req.Password != nil {
		if err := val.ValidatePassword(req.GetPassword()); err != nil {
			violations = append(violations, fieldViolation("password", err))
		}
	}

	return violations
}
