package role

import (
	"context"
	"log"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/service/role"
	"github.com/steve-mir/go-auth-system/pb"
)

// Server implements the gRPC RoleService
type Server struct {
	pb.UnimplementedRoleServiceServer
	roleService role.Service
}

// NewServer creates a new gRPC role server
func NewServer(roleService role.Service) *Server {
	return &Server{
		roleService: roleService,
	}
}

// CreateRole creates a new role
func (s *Server) CreateRole(ctx context.Context, req *pb.CreateRoleRequest) (*pb.CreateRoleResponse, error) {
	// Validate request
	if req.Name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	// Convert string permissions to Permission structs
	var permissions []role.Permission
	for _, perm := range req.Permissions {
		// Parse permission string (format: "resource:action" or "resource:action:scope")
		parts := strings.Split(perm, ":")
		if len(parts) >= 2 {
			permission := role.Permission{
				Resource: parts[0],
				Action:   parts[1],
			}
			if len(parts) > 2 {
				permission.Scope = parts[2]
			}
			permissions = append(permissions, permission)
		}
	}

	// Convert gRPC request to service request
	createReq := role.CreateRoleRequest{
		Name:        req.Name,
		Description: req.Description,
		Permissions: permissions,
	}

	// Call service
	roleResp, err := s.roleService.CreateRole(ctx, createReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert Permission structs back to strings
	var permissionStrings []string
	for _, perm := range roleResp.Permissions {
		permissionStrings = append(permissionStrings, perm.String())
	}

	// Convert service response to gRPC response
	grpcRole := &pb.Role{
		Id:          roleResp.ID.String(),
		Name:        roleResp.Name,
		Description: roleResp.Description,
		Permissions: permissionStrings,
		CreatedAt:   timestamppb.New(roleResp.CreatedAt),
		UpdatedAt:   timestamppb.New(roleResp.UpdatedAt),
	}

	return &pb.CreateRoleResponse{
		Role: grpcRole,
	}, nil
}

// GetRole retrieves a role by ID
func (s *Server) GetRole(ctx context.Context, req *pb.GetRoleRequest) (*pb.GetRoleResponse, error) {
	// Validate request
	if req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "role_id is required")
	}

	// Parse UUID from string
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid role_id format")
	}

	// Call service
	roleResp, err := s.roleService.GetRole(ctx, roleID)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert Permission structs back to strings
	var permissionStrings []string
	for _, perm := range roleResp.Permissions {
		permissionStrings = append(permissionStrings, perm.String())
	}

	// Convert service response to gRPC response
	grpcRole := &pb.Role{
		Id:          roleResp.ID.String(),
		Name:        roleResp.Name,
		Description: roleResp.Description,
		Permissions: permissionStrings,
		CreatedAt:   timestamppb.New(roleResp.CreatedAt),
		UpdatedAt:   timestamppb.New(roleResp.UpdatedAt),
	}

	return &pb.GetRoleResponse{
		Role: grpcRole,
	}, nil
}

// UpdateRole updates an existing role
func (s *Server) UpdateRole(ctx context.Context, req *pb.UpdateRoleRequest) (*pb.UpdateRoleResponse, error) {
	// Validate request
	if req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "role_id is required")
	}

	// Parse UUID from string
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid role_id format")
	}

	// Convert string permissions to Permission structs
	var permissions []role.Permission
	for _, perm := range req.Permissions {
		// Parse permission string (format: "resource:action" or "resource:action:scope")
		parts := strings.Split(perm, ":")
		if len(parts) >= 2 {
			permission := role.Permission{
				Resource: parts[0],
				Action:   parts[1],
			}
			if len(parts) > 2 {
				permission.Scope = parts[2]
			}
			permissions = append(permissions, permission)
		}
	}

	// Convert gRPC request to service request
	updateReq := role.UpdateRoleRequest{
		Permissions: permissions,
	}

	if req.Name != nil {
		updateReq.Name = req.Name
	}
	if req.Description != nil {
		updateReq.Description = req.Description
	}

	// Call service
	roleResp, err := s.roleService.UpdateRole(ctx, roleID, updateReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert Permission structs back to strings
	var permissionStrings []string
	for _, perm := range roleResp.Permissions {
		permissionStrings = append(permissionStrings, perm.String())
	}

	// Convert service response to gRPC response
	grpcRole := &pb.Role{
		Id:          roleResp.ID.String(),
		Name:        roleResp.Name,
		Description: roleResp.Description,
		Permissions: permissionStrings,
		CreatedAt:   timestamppb.New(roleResp.CreatedAt),
		UpdatedAt:   timestamppb.New(roleResp.UpdatedAt),
	}

	return &pb.UpdateRoleResponse{
		Role: grpcRole,
	}, nil
}

// DeleteRole deletes a role
func (s *Server) DeleteRole(ctx context.Context, req *pb.DeleteRoleRequest) (*pb.DeleteRoleResponse, error) {
	// Validate request
	if req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "role_id is required")
	}

	// Parse UUID from string
	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid role_id format")
	}

	// Call service
	err = s.roleService.DeleteRole(ctx, roleID)
	if err != nil {
		return nil, s.handleError(err)
	}

	return &pb.DeleteRoleResponse{
		Success: true,
		Message: "Role deleted successfully",
	}, nil
}

// ListRoles retrieves a paginated list of roles
func (s *Server) ListRoles(ctx context.Context, req *pb.ListRolesRequest) (*pb.ListRolesResponse, error) {
	// Convert gRPC request to service request
	listReq := role.ListRolesRequest{
		Limit:  int(req.PageSize),
		Offset: int(req.Page-1) * int(req.PageSize),
	}

	// Call service
	resp, err := s.roleService.ListRoles(ctx, listReq)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert roles to gRPC format
	var roles []*pb.Role
	for _, r := range resp.Roles {
		// Convert Permission structs back to strings
		var permissionStrings []string
		for _, perm := range r.Permissions {
			permissionStrings = append(permissionStrings, perm.String())
		}

		grpcRole := &pb.Role{
			Id:          r.ID.String(),
			Name:        r.Name,
			Description: r.Description,
			Permissions: permissionStrings,
			CreatedAt:   timestamppb.New(r.CreatedAt),
			UpdatedAt:   timestamppb.New(r.UpdatedAt),
		}
		roles = append(roles, grpcRole)
	}

	// Calculate pagination info
	totalPages := int32((resp.Total + int64(req.PageSize) - 1) / int64(req.PageSize))

	return &pb.ListRolesResponse{
		Roles:      roles,
		TotalCount: int32(resp.Total),
		Page:       req.Page,
		PageSize:   req.PageSize,
		TotalPages: totalPages,
	}, nil
}

// AssignRole assigns a role to a user
func (s *Server) AssignRole(ctx context.Context, req *pb.AssignRoleRequest) (*pb.AssignRoleResponse, error) {
	// Validate request
	if req.UserId == "" || req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}

	// Parse UUIDs from strings
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id format")
	}

	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid role_id format")
	}

	var assignedBy uuid.UUID
	if req.AssignedBy != "" {
		assignedBy, err = uuid.Parse(req.AssignedBy)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid assigned_by format")
		}
	}

	// Call service
	err = s.roleService.AssignRoleToUser(ctx, userID, roleID, assignedBy)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Create a basic user role response (since the service doesn't return detailed info)
	grpcUserRole := &pb.UserRole{
		UserId:     req.UserId,
		RoleId:     req.RoleId,
		AssignedAt: timestamppb.Now(),
		AssignedBy: req.AssignedBy,
	}

	return &pb.AssignRoleResponse{
		Success:  true,
		Message:  "Role assigned successfully",
		UserRole: grpcUserRole,
	}, nil
}

// UnassignRole removes a role from a user
func (s *Server) UnassignRole(ctx context.Context, req *pb.UnassignRoleRequest) (*pb.UnassignRoleResponse, error) {
	// Validate request
	if req.UserId == "" || req.RoleId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and role_id are required")
	}

	// Parse UUIDs from strings
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id format")
	}

	roleID, err := uuid.Parse(req.RoleId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid role_id format")
	}

	// Call service
	err = s.roleService.RemoveRoleFromUser(ctx, userID, roleID)
	if err != nil {
		return nil, s.handleError(err)
	}

	return &pb.UnassignRoleResponse{
		Success: true,
		Message: "Role unassigned successfully",
	}, nil
}

// GetUserRoles retrieves all roles assigned to a user
func (s *Server) GetUserRoles(ctx context.Context, req *pb.GetUserRolesRequest) (*pb.GetUserRolesResponse, error) {
	// Validate request
	if req.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	// Parse UUID from string
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id format")
	}

	// Call service to get user roles
	roles, err := s.roleService.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Get user permissions
	permissions, err := s.roleService.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Convert roles to user roles format
	var userRoles []*pb.UserRole
	for _, role := range roles {
		grpcUserRole := &pb.UserRole{
			UserId:     req.UserId,
			RoleId:     role.ID.String(),
			RoleName:   role.Name,
			AssignedAt: timestamppb.New(role.CreatedAt), // Using role creation time as fallback
		}
		userRoles = append(userRoles, grpcUserRole)
	}

	// Convert permissions to strings
	var permissionStrings []string
	for _, perm := range permissions {
		permissionStrings = append(permissionStrings, perm.String())
	}

	return &pb.GetUserRolesResponse{
		UserRoles:   userRoles,
		Permissions: permissionStrings,
	}, nil
}

// ValidatePermission checks if a user has a specific permission
func (s *Server) ValidatePermission(ctx context.Context, req *pb.ValidatePermissionRequest) (*pb.ValidatePermissionResponse, error) {
	// Validate request
	if req.UserId == "" || req.Resource == "" || req.Action == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id, resource, and action are required")
	}

	// Parse UUID from string
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user_id format")
	}

	// Create permission struct
	permission := role.Permission{
		Resource: req.Resource,
		Action:   req.Action,
		Scope:    req.Scope,
	}

	// Call service
	allowed, err := s.roleService.ValidatePermission(ctx, userID, permission)
	if err != nil {
		return nil, s.handleError(err)
	}

	// Create response
	reason := "Permission granted"
	if !allowed {
		reason = "Permission denied"
	}

	return &pb.ValidatePermissionResponse{
		Allowed:       allowed,
		Reason:        reason,
		MatchingRoles: []string{}, // TODO: Implement when service provides this info
	}, nil
}

// handleError converts service errors to gRPC errors
func (s *Server) handleError(err error) error {
	log.Printf("gRPC Role Service Error: %v", err)

	// TODO: Implement proper error type checking based on your error types
	// For now, return internal error
	return status.Error(codes.Internal, "internal server error")
}
