package user

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/steve-mir/go-auth-system/internal/service/user"
	"github.com/steve-mir/go-auth-system/pb"
)

// Server implements the gRPC UserService
type Server struct {
	pb.UnimplementedUserServiceServer
	userService user.UserService
}

// NewServer creates a new gRPC user server
func NewServer(userService user.UserService) *Server {
	return &Server{
		userService: userService,
	}
}

// GetProfile retrieves user profile information
func (s *Server) GetProfile(ctx context.Context, req *pb.GetProfileRequest) (*pb.GetProfileResponse, error) {
	// Validate request
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Call service
	profile, err := s.userService.GetProfile(ctx, req.UserId)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert service response to gRPC response
	userProfile := &pb.UserProfile{
		UserId:        profile.ID.String(),
		Email:         profile.Email,
		Username:      profile.Username,
		FirstName:     profile.FirstName,
		LastName:      profile.LastName,
		Phone:         profile.Phone,
		EmailVerified: profile.Verified.Email,
		PhoneVerified: profile.Verified.Phone,
		AccountLocked: profile.Status.Locked,
		Roles:         profile.Roles,
		CreatedAt:     timestamppb.New(profile.CreatedAt),
		UpdatedAt:     timestamppb.New(profile.UpdatedAt),
	}

	if profile.Status.LastLogin != nil {
		userProfile.LastLoginAt = timestamppb.New(*profile.Status.LastLogin)
	}

	return &pb.GetProfileResponse{
		UserProfile: userProfile,
	}, nil
}

// UpdateProfile updates user profile information
func (s *Server) UpdateProfile(ctx context.Context, req *pb.UpdateProfileRequest) (*pb.UpdateProfileResponse, error) {
	// Validate request
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Convert gRPC request to service request
	updateReq := &user.UpdateProfileRequest{}

	if req.FirstName != nil {
		updateReq.FirstName = req.FirstName
	}
	if req.LastName != nil {
		updateReq.LastName = req.LastName
	}
	if req.Phone != nil {
		updateReq.Phone = req.Phone
	}
	if req.Username != nil {
		updateReq.Username = req.Username
	}

	// Call service
	profile, err := s.userService.UpdateProfile(ctx, req.UserId, updateReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert service response to gRPC response
	userProfile := &pb.UserProfile{
		UserId:        profile.ID.String(),
		Email:         profile.Email,
		Username:      profile.Username,
		FirstName:     profile.FirstName,
		LastName:      profile.LastName,
		Phone:         profile.Phone,
		EmailVerified: profile.Verified.Email,
		PhoneVerified: profile.Verified.Phone,
		AccountLocked: profile.Status.Locked,
		Roles:         profile.Roles,
		CreatedAt:     timestamppb.New(profile.CreatedAt),
		UpdatedAt:     timestamppb.New(profile.UpdatedAt),
	}

	if profile.Status.LastLogin != nil {
		userProfile.LastLoginAt = timestamppb.New(*profile.Status.LastLogin)
	}

	return &pb.UpdateProfileResponse{
		UserProfile: userProfile,
		Message:     "Profile updated successfully",
	}, nil
}

// DeleteUser deletes a user account
func (s *Server) DeleteUser(ctx context.Context, req *pb.DeleteUserRequest) (*pb.DeleteUserResponse, error) {
	// Validate request
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Call service
	err := s.userService.DeleteUser(ctx, req.UserId)
	if err != nil {
		return nil, s.handleError(err)
	}

	return &pb.DeleteUserResponse{
		Success: true,
		Message: "User deleted successfully",
	}, nil
}

// ListUsers retrieves a paginated list of users
func (s *Server) ListUsers(ctx context.Context, req *pb.ListUsersRequest) (*pb.ListUsersResponse, error) {
	// Convert gRPC request to service request
	listReq := &user.ListUsersRequest{
		Page:     req.Page,
		PageSize: req.PageSize,
		Search:   req.Search,
		SortBy:   req.SortBy,
		SortDesc: req.SortOrder == "desc",
	}

	// Call service
	resp, err := s.userService.ListUsers(ctx, listReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert users to gRPC format
	var users []*pb.UserProfile
	for _, u := range resp.Users {
		userProfile := &pb.UserProfile{
			UserId:        u.ID.String(),
			Email:         u.Email,
			Username:      u.Username,
			FirstName:     u.FirstName,
			LastName:      u.LastName,
			Phone:         u.Phone,
			EmailVerified: u.Verified.Email,
			PhoneVerified: u.Verified.Phone,
			AccountLocked: u.Status.Locked,
			Roles:         u.Roles,
			CreatedAt:     timestamppb.New(u.CreatedAt),
			UpdatedAt:     timestamppb.New(u.UpdatedAt),
		}

		if u.Status.LastLogin != nil {
			userProfile.LastLoginAt = timestamppb.New(*u.Status.LastLogin)
		}

		users = append(users, userProfile)
	}

	return &pb.ListUsersResponse{
		Users:      users,
		TotalCount: int32(resp.Total),
		Page:       resp.Page,
		PageSize:   resp.PageSize,
		TotalPages: resp.TotalPages,
	}, nil
}

// ChangePassword changes a user's password
func (s *Server) ChangePassword(ctx context.Context, req *pb.ChangePasswordRequest) (*pb.ChangePasswordResponse, error) {
	// Validate request
	if req.UserId == "" || req.CurrentPassword == "" || req.NewPassword == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, current_password, and new_password are required")
	}

	// Convert gRPC request to service request
	changeReq := &user.ChangePasswordRequest{
		CurrentPassword: req.CurrentPassword,
		NewPassword:     req.NewPassword,
	}

	// Call service
	err := s.userService.ChangePassword(ctx, req.UserId, changeReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	return &pb.ChangePasswordResponse{
		Success: true,
		Message: "Password changed successfully",
	}, nil
}

// VerifyEmail verifies a user's email address
func (s *Server) VerifyEmail(ctx context.Context, req *pb.VerifyEmailRequest) (*pb.VerifyEmailResponse, error) {
	// TODO: Implement email verification when the service method is available
	return &pb.VerifyEmailResponse{
		Success: false,
		Message: "Email verification not implemented yet",
	}, status.Error(codes.Unimplemented, "email verification not implemented")
}

// VerifyPhone verifies a user's phone number
func (s *Server) VerifyPhone(ctx context.Context, req *pb.VerifyPhoneRequest) (*pb.VerifyPhoneResponse, error) {
	// TODO: Implement phone verification when the service method is available
	return &pb.VerifyPhoneResponse{
		Success: false,
		Message: "Phone verification not implemented yet",
	}, status.Error(codes.Unimplemented, "phone verification not implemented")
}

// handleError converts service errors to gRPC errors
func (s *Server) handleError(err error) error {
	log.Printf("gRPC User Service Error: %v", err)

	// TODO: Implement proper error type checking based on your error types
	// For now, return internal error
	return status.Error(codes.Internal, "internal server error")
}
