package rest

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/steve-mir/go-auth-system/internal/errors"
)

// APIResponse represents a standard API response
type APIResponse struct {
	Success   bool        `json:"success"`
	Data      interface{} `json:"data,omitempty"`
	Error     *APIError   `json:"error,omitempty"`
	RequestID string      `json:"request_id,omitempty"`
	Timestamp time.Time   `json:"timestamp"`
}

// APIError represents an API error response
type APIError struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details,omitempty"`
}

// PaginationMeta represents pagination metadata
type PaginationMeta struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// PaginatedResponse represents a paginated API response
type PaginatedResponse struct {
	Success    bool            `json:"success"`
	Data       interface{}     `json:"data"`
	Pagination *PaginationMeta `json:"pagination"`
	RequestID  string          `json:"request_id,omitempty"`
	Timestamp  time.Time       `json:"timestamp"`
}

// successResponse sends a successful API response
func (s *Server) successResponse(c *gin.Context, statusCode int, data interface{}) {
	response := APIResponse{
		Success:   true,
		Data:      data,
		RequestID: s.getRequestID(c),
		Timestamp: time.Now(),
	}

	c.JSON(statusCode, response)
}

// errorResponse sends an error API response
func (s *Server) errorResponse(c *gin.Context, statusCode int, code, message string, details interface{}) {
	response := APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
			Details: details,
		},
		RequestID: s.getRequestID(c),
		Timestamp: time.Now(),
	}

	c.JSON(statusCode, response)
}

// paginatedResponse sends a paginated API response
func (s *Server) paginatedResponse(c *gin.Context, statusCode int, data interface{}, pagination *PaginationMeta) {
	response := PaginatedResponse{
		Success:    true,
		Data:       data,
		Pagination: pagination,
		RequestID:  s.getRequestID(c),
		Timestamp:  time.Now(),
	}

	c.JSON(statusCode, response)
}

// handleServiceError converts service errors to appropriate HTTP responses
func (s *Server) handleServiceError(c *gin.Context, err error) {
	if appErr, ok := err.(*errors.AppError); ok {
		switch appErr.Type {
		case errors.ErrorTypeValidation:
			s.errorResponse(c, http.StatusBadRequest, appErr.Code, appErr.Message, appErr.Details)
		case errors.ErrorTypeAuthentication:
			s.errorResponse(c, http.StatusUnauthorized, appErr.Code, appErr.Message, appErr.Details)
		case errors.ErrorTypeAuthorization:
			s.errorResponse(c, http.StatusForbidden, appErr.Code, appErr.Message, appErr.Details)
		case errors.ErrorTypeNotFound:
			s.errorResponse(c, http.StatusNotFound, appErr.Code, appErr.Message, appErr.Details)
		case errors.ErrorTypeConflict:
			s.errorResponse(c, http.StatusConflict, appErr.Code, appErr.Message, appErr.Details)
		case errors.ErrorTypeRateLimit:
			s.errorResponse(c, http.StatusTooManyRequests, appErr.Code, appErr.Message, appErr.Details)
		case errors.ErrorTypeExternal:
			s.errorResponse(c, http.StatusBadGateway, appErr.Code, appErr.Message, appErr.Details)
		default:
			s.errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred", nil)
		}
	} else {
		// Unknown error type
		s.errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", "An internal error occurred", nil)
	}
}

// getRequestID extracts request ID from context
func (s *Server) getRequestID(c *gin.Context) string {
	if requestID, exists := c.Get("request_id"); exists {
		if id, ok := requestID.(string); ok {
			return id
		}
	}
	return ""
}

// ValidationError represents a field validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
	Value   string `json:"value,omitempty"`
}

// validationErrorResponse sends a validation error response
func (s *Server) validationErrorResponse(c *gin.Context, validationErrors []ValidationError) {
	s.errorResponse(c, http.StatusBadRequest, "VALIDATION_ERROR", "Request validation failed", map[string]interface{}{
		"validation_errors": validationErrors,
	})
}

// Common HTTP status responses

// badRequestResponse sends a 400 Bad Request response
func (s *Server) badRequestResponse(c *gin.Context, message string, details interface{}) {
	s.errorResponse(c, http.StatusBadRequest, "BAD_REQUEST", message, details)
}

// unauthorizedResponse sends a 401 Unauthorized response
func (s *Server) unauthorizedResponse(c *gin.Context, message string) {
	s.errorResponse(c, http.StatusUnauthorized, "UNAUTHORIZED", message, nil)
}

// forbiddenResponse sends a 403 Forbidden response
func (s *Server) forbiddenResponse(c *gin.Context, message string) {
	s.errorResponse(c, http.StatusForbidden, "FORBIDDEN", message, nil)
}

// notFoundResponse sends a 404 Not Found response
func (s *Server) notFoundResponse(c *gin.Context, message string) {
	s.errorResponse(c, http.StatusNotFound, "NOT_FOUND", message, nil)
}

// conflictResponse sends a 409 Conflict response
func (s *Server) conflictResponse(c *gin.Context, message string, details interface{}) {
	s.errorResponse(c, http.StatusConflict, "CONFLICT", message, details)
}

// tooManyRequestsResponse sends a 429 Too Many Requests response
func (s *Server) tooManyRequestsResponse(c *gin.Context, message string, details interface{}) {
	s.errorResponse(c, http.StatusTooManyRequests, "TOO_MANY_REQUESTS", message, details)
}

// internalServerErrorResponse sends a 500 Internal Server Error response
func (s *Server) internalServerErrorResponse(c *gin.Context, message string) {
	s.errorResponse(c, http.StatusInternalServerError, "INTERNAL_ERROR", message, nil)
}

// calculatePagination calculates pagination metadata
func calculatePagination(page, limit int, total int64) *PaginationMeta {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = 10
	}

	totalPages := int((total + int64(limit) - 1) / int64(limit))
	if totalPages < 1 {
		totalPages = 1
	}

	return &PaginationMeta{
		Page:       page,
		Limit:      limit,
		Total:      total,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1,
	}
}
