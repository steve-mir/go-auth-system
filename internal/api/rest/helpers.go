package rest

import (
	"strings"

	"github.com/gin-gonic/gin"
	// "github.com/steve-mir/go-auth-system/internal/interfaces"
)

// Helper methods for REST API handlers

// bindAndValidate binds JSON request body and validates it
func (s *Server) bindAndValidate(c *gin.Context, obj interface{}) bool {
	if err := c.ShouldBindJSON(obj); err != nil {
		s.badRequestResponse(c, "Invalid request body", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}
	return true
}

// // parseUUIDParam parses UUID parameter from URL
// func (s *Server) parseUUIDParam(c *gin.Context, param string) (string, bool) {
// 	value := c.Param(param)
// 	if value == "" {
// 		s.badRequestResponse(c, "Missing "+param+" parameter", nil)
// 		return "", false
// 	}

// 	if _, err := uuid.Parse(value); err != nil {
// 		s.badRequestResponse(c, "Invalid "+param+" format", nil)
// 		return "", false
// 	}

// 	return value, true
// }

// // GetPaginationParams extracts pagination parameters from query string
// func (s *Server) GetPaginationParams(c *gin.Context) (page, limit int, valid bool) {
// 	pageStr := c.DefaultQuery("page", "1")
// 	limitStr := c.DefaultQuery("limit", "10")

// 	page, err := strconv.Atoi(pageStr)
// 	if err != nil || page < 1 {
// 		s.badRequestResponse(c, "Invalid page parameter", nil)
// 		return 0, 0, false
// 	}

// 	limit, err = strconv.Atoi(limitStr)
// 	if err != nil || limit < 1 || limit > 100 {
// 		s.badRequestResponse(c, "Invalid limit parameter (must be between 1 and 100)", nil)
// 		return 0, 0, false
// 	}

// 	return page, limit, true
// }

// TODO: Refactor
// getUserContext extracts user information from context
func (s *Server) getUserContext(c *gin.Context) (userID, email, username string, roles []string) {
	if uid, exists := c.Get("user_id"); exists {
		userID = uid.(string)
	}
	if e, exists := c.Get("email"); exists {
		email = e.(string)
	}
	if u, exists := c.Get("username"); exists {
		username = u.(string)
	}
	if r, exists := c.Get("roles"); exists {
		roles = r.([]string)
	}

	if e, exists := c.Get("user_email"); exists {
		email, _ = e.(string)
	}
	if u, exists := c.Get("user_username"); exists {
		username, _ = u.(string)
	}
	if r, exists := c.Get("user_roles"); exists {
		roles, _ = r.([]string)
	}
	return
}

// // getClientInfo extracts client IP and user agent
// func (s *Server) getClientInfo(c *gin.Context) (ipAddress, userAgent string) {
// 	ipAddress = c.ClientIP()
// 	userAgent = c.Request.UserAgent()
// 	return
// }

// getClientInfo extracts client information from request
func (s *Server) getClientInfo(c *gin.Context) (ipAddress, userAgent string) {
	// Get IP address (consider X-Forwarded-For for load balancers)
	ipAddress = c.ClientIP()
	if forwarded := c.GetHeader("X-Forwarded-For"); forwarded != "" {
		// Take the first IP in the chain
		if idx := strings.Index(forwarded, ","); idx != -1 {
			ipAddress = strings.TrimSpace(forwarded[:idx])
		} else {
			ipAddress = strings.TrimSpace(forwarded)
		}
	}

	userAgent = c.GetHeader("User-Agent")
	return
}

// Response helper methods

// successResponse sends a successful response
// func (s *Server) successResponse(c *gin.Context, statusCode int, data interface{}) {
// 	c.JSON(statusCode, gin.H{
// 		"success": true,
// 		"data":    data,
// 	})
// }

// paginatedResponse sends a paginated response
// func (s *Server) paginatedResponse(c *gin.Context, statusCode int, data interface{}, pagination interfaces.PaginationInfo) {
// 	c.JSON(statusCode, gin.H{
// 		"success":    true,
// 		"data":       data,
// 		"pagination": pagination,
// 	})
// }

// // badRequestResponse sends a bad request response
// func (s *Server) badRequestResponse(c *gin.Context, message string, details interface{}) {
// 	c.JSON(http.StatusBadRequest, gin.H{
// 		"success": false,
// 		"error": gin.H{
// 			"code":    "BAD_REQUEST",
// 			"message": message,
// 			"details": details,
// 		},
// 	})
// }

// // unauthorizedResponse sends an unauthorized response
// func (s *Server) unauthorizedResponse(c *gin.Context, message string) {
// 	c.JSON(http.StatusUnauthorized, gin.H{
// 		"success": false,
// 		"error": gin.H{
// 			"code":    "UNAUTHORIZED",
// 			"message": message,
// 		},
// 	})
// }

// forbiddenResponse sends a forbidden response
// func (s *Server) forbiddenResponse(c *gin.Context, message string) {
// 	c.JSON(http.StatusForbidden, gin.H{
// 		"success": false,
// 		"error": gin.H{
// 			"code":    "FORBIDDEN",
// 			"message": message,
// 		},
// 	})
// }

// // notFoundResponse sends a not found response
// func (s *Server) notFoundResponse(c *gin.Context, message string) {
// 	c.JSON(http.StatusNotFound, gin.H{
// 		"success": false,
// 		"error": gin.H{
// 			"code":    "NOT_FOUND",
// 			"message": message,
// 		},
// 	})
// }

// // internalServerErrorResponse sends an internal server error response
// func (s *Server) internalServerErrorResponse(c *gin.Context, message string) {
// 	c.JSON(http.StatusInternalServerError, gin.H{
// 		"success": false,
// 		"error": gin.H{
// 			"code":    "INTERNAL_SERVER_ERROR",
// 			"message": message,
// 		},
// 	})
// }

// // handleServiceError handles service layer errors
// func (s *Server) handleServiceError(c *gin.Context, err error) {
// 	// You can implement more sophisticated error handling here
// 	// based on your error types and requirements
// 	s.internalServerErrorResponse(c, err.Error())
// }

// Utility functions

// calculatePagination calculates pagination information
// func calculatePagination(page, limit int, total int64) PaginationInfo {
// 	totalPages := int((total + int64(limit) - 1) / int64(limit))

// 	return PaginationInfo{
// 		Page:       page,
// 		Limit:      limit,
// 		Total:      total,
// 		TotalPages: totalPages,
// 		HasNext:    page < totalPages,
// 		HasPrev:    page > 1,
// 	}
// }

// PaginationInfo represents pagination metadata
type PaginationInfo struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// // ValidatePermissionRequest represents a permission validation request
// type ValidatePermissionRequest struct {
// 	UserID     string                 `json:"user_id" binding:"required"`
// 	Resource   string                 `json:"resource" binding:"required"`
// 	Action     string                 `json:"action" binding:"required"`
// 	Scope      string                 `json:"scope,omitempty"`
// 	Attributes map[string]interface{} `json:"attributes,omitempty"`
// }
