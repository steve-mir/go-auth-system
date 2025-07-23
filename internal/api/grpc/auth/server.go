package auth

import (
	"context"
	"log"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/steve-mir/go-auth-system/internal/service/auth"
	"github.com/steve-mir/go-auth-system/pb"
)

// Server implements the gRPC AuthService
type Server struct {
	pb.UnimplementedAuthServiceServer
	authService auth.AuthService
}

// NewServer creates a new gRPC auth server
func NewServer(authService auth.AuthService) *Server {
	return &Server{
		authService: authService,
	}
}

// Register handles user registration
func (s *Server) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	// Validate request
	if req.Email == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "email and password are required")
	}

	// Convert gRPC request to service request
	registerReq := &auth.RegisterRequest{
		Email:     req.Email,
		Username:  req.Username,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
		Phone:     req.Phone,
	}

	// Call service
	resp, err := s.authService.Register(ctx, registerReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert service response to gRPC response
	return &pb.RegisterResponse{
		UserId:                    resp.UserID.String(),
		Email:                     resp.Email,
		Username:                  resp.Username,
		CreatedAt:                 timestamppb.New(resp.CreatedAt),
		EmailVerificationRequired: true, // Set based on your business logic
	}, nil
}

// Login handles user authentication
func (s *Server) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	// Validate request
	if req.Identifier == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "identifier and password are required")
	}

	// Convert gRPC request to service request
	loginReq := &auth.LoginRequest{
		Email:      req.Identifier, // Assuming identifier is email for now
		Password:   req.Password,
		IPAddress:  req.IpAddress,
		UserAgent:  req.UserAgent,
		RememberMe: req.RememberMe,
	}

	// Call service
	resp, err := s.authService.Login(ctx, loginReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Get user profile separately
	userProfile, err := s.authService.GetUserProfile(ctx, resp.AccessToken)
	if err != nil {
		// If we can't get profile, create a minimal one
		userProfile = &auth.UserProfile{
			ID:       resp.UserID,
			Email:    resp.Email,
			Username: resp.Username,
		}
	}

	// Convert user profile
	grpcAuthUserProfile := &pb.AuthUserProfile{
		UserId:        userProfile.ID.String(),
		Email:         userProfile.Email,
		Username:      userProfile.Username,
		FirstName:     userProfile.FirstName,
		LastName:      userProfile.LastName,
		Phone:         userProfile.Phone,
		EmailVerified: true, // Set based on your business logic
		PhoneVerified: false,
		AccountLocked: false,
		Roles:         userProfile.Roles,
		CreatedAt:     timestamppb.New(userProfile.CreatedAt),
		UpdatedAt:     timestamppb.New(userProfile.UpdatedAt),
	}

	// Convert service response to gRPC response
	return &pb.LoginResponse{
		UserId:       resp.UserID.String(),
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    timestamppb.New(resp.ExpiresAt),
		UserProfile:  grpcAuthUserProfile,
		MfaRequired:  false, // Set based on your business logic
		MfaToken:     "",
	}, nil
}

// Logout handles user logout
func (s *Server) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	// Validate request
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access token is required")
	}

	// Convert gRPC request to service request
	logoutReq := auth.LogoutRequest{
		AccessToken:  req.AccessToken,
		RefreshToken: req.RefreshToken,
	}

	// Call service
	err := s.authService.Logout(ctx, &logoutReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	return &pb.LogoutResponse{
		Success: true,
		Message: "Successfully logged out",
	}, nil
}

// RefreshToken handles token refresh
func (s *Server) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.TokenResponse, error) {
	// Validate request
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token is required")
	}

	// Convert gRPC request to service request
	refreshReq := &auth.RefreshTokenRequest{
		RefreshToken: req.RefreshToken,
	}

	// Call service
	resp, err := s.authService.RefreshToken(ctx, refreshReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert service response to gRPC response
	return &pb.TokenResponse{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		ExpiresAt:    timestamppb.New(resp.ExpiresAt),
		TokenType:    resp.TokenType,
	}, nil
}

// ValidateToken handles token validation
func (s *Server) ValidateToken(ctx context.Context, req *pb.ValidateTokenRequest) (*pb.ValidateTokenResponse, error) {
	// Validate request
	if req.Token == "" {
		return nil, status.Error(codes.InvalidArgument, "token is required")
	}

	// Convert gRPC request to service request
	validateReq := &auth.ValidateTokenRequest{
		Token: req.Token,
	}

	// Call service
	claims, err := s.authService.ValidateToken(ctx, validateReq)
	if err != nil {
		return &pb.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	// Convert claims - using available fields from ValidateTokenResponse
	tokenClaims := &pb.TokenClaims{
		UserId:    claims.UserID,
		Email:     claims.Email,
		Username:  claims.Username,
		Roles:     claims.Roles,
		ExpiresAt: timestamppb.New(claims.ExpiresAt),
		// Note: Some fields may not be available in the service response
		Permissions: []string{},                        // Default empty if not available
		IssuedAt:    timestamppb.New(claims.ExpiresAt), // Using ExpiresAt as fallback
		Issuer:      "",
		Audience:    "",
	}

	return &pb.ValidateTokenResponse{
		Valid:     claims.Valid,
		UserId:    claims.UserID,
		Roles:     claims.Roles,
		ExpiresAt: timestamppb.New(claims.ExpiresAt),
		Claims:    tokenClaims,
	}, nil
}

// handleError converts service errors to gRPC errors
func (s *Server) handleError(err error) error {
	log.Printf("gRPC Auth Service Error: %v", err)

	// TODO: Implement proper error type checking based on your error types
	// For now, return internal error
	return status.Error(codes.Internal, "internal server error")
}
