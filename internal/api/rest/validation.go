package rest

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

// Validator instance
var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom tag name function to use json tags
	validate.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		return name
	})
}

// validateRequest validates a request struct and returns validation errors
func (s *Server) validateRequest(c *gin.Context, req interface{}) bool {
	if err := validate.Struct(req); err != nil {
		var validationErrors []ValidationError

		if validationErrs, ok := err.(validator.ValidationErrors); ok {
			for _, validationErr := range validationErrs {
				validationErrors = append(validationErrors, ValidationError{
					Field:   validationErr.Field(),
					Message: getValidationErrorMessage(validationErr),
					Value:   fmt.Sprintf("%v", validationErr.Value()),
				})
			}
		}

		s.validationErrorResponse(c, validationErrors)
		return false
	}

	return true
}

// getValidationErrorMessage returns a human-readable validation error message
func getValidationErrorMessage(err validator.FieldError) string {
	switch err.Tag() {
	case "required":
		return "This field is required"
	case "email":
		return "Must be a valid email address"
	case "min":
		return fmt.Sprintf("Must be at least %s characters long", err.Param())
	case "max":
		return fmt.Sprintf("Must be at most %s characters long", err.Param())
	case "len":
		return fmt.Sprintf("Must be exactly %s characters long", err.Param())
	case "e164":
		return "Must be a valid phone number in E.164 format"
	case "uuid":
		return "Must be a valid UUID"
	case "oneof":
		return fmt.Sprintf("Must be one of: %s", err.Param())
	case "gte":
		return fmt.Sprintf("Must be greater than or equal to %s", err.Param())
	case "lte":
		return fmt.Sprintf("Must be less than or equal to %s", err.Param())
	case "gt":
		return fmt.Sprintf("Must be greater than %s", err.Param())
	case "lt":
		return fmt.Sprintf("Must be less than %s", err.Param())
	default:
		return fmt.Sprintf("Validation failed for tag '%s'", err.Tag())
	}
}

// // bindAndValidate binds JSON request and validates it
// func (s *Server) bindAndValidate(c *gin.Context, req interface{}) bool {
// 	if err := c.ShouldBindJSON(req); err != nil {
// 		s.badRequestResponse(c, "Invalid JSON format", map[string]interface{}{
// 			"error": err.Error(),
// 		})
// 		return false
// 	}

// 	return s.validateRequest(c, req)
// }

// bindQueryAndValidate binds query parameters and validates them
func (s *Server) bindQueryAndValidate(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindQuery(req); err != nil {
		s.badRequestResponse(c, "Invalid query parameters", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	return s.validateRequest(c, req)
}

// bindURIAndValidate binds URI parameters and validates them
func (s *Server) bindURIAndValidate(c *gin.Context, req interface{}) bool {
	if err := c.ShouldBindUri(req); err != nil {
		s.badRequestResponse(c, "Invalid URI parameters", map[string]interface{}{
			"error": err.Error(),
		})
		return false
	}

	return s.validateRequest(c, req)
}

// PaginationQuery represents pagination query parameters
type PaginationQuery struct {
	Page  int `form:"page" validate:"omitempty,gte=1"`
	Limit int `form:"limit" validate:"omitempty,gte=1,lte=100"`
}

// GetPaginationParams extracts and validates pagination parameters
func (s *Server) GetPaginationParams(c *gin.Context) (page, limit int, valid bool) {
	var query PaginationQuery

	if !s.bindQueryAndValidate(c, &query) {
		return 0, 0, false
	}

	// Set defaults
	page = query.Page
	if page < 1 {
		page = 1
	}

	limit = query.Limit
	if limit < 1 {
		limit = 10
	}
	if limit > 100 {
		limit = 100
	}

	return page, limit, true
}

// SortQuery represents sorting query parameters
type SortQuery struct {
	SortBy    string `form:"sort_by" validate:"omitempty"`
	SortOrder string `form:"sort_order" validate:"omitempty,oneof=asc desc"`
}

// GetSortParams extracts and validates sort parameters
func (s *Server) GetSortParams(c *gin.Context, allowedFields []string) (sortBy, sortOrder string, valid bool) {
	var query SortQuery

	if !s.bindQueryAndValidate(c, &query) {
		return "", "", false
	}

	sortBy = query.SortBy
	sortOrder = query.SortOrder

	// Set defaults
	if sortOrder == "" {
		sortOrder = "asc"
	}

	// Validate sort field if provided
	if sortBy != "" && len(allowedFields) > 0 {
		allowed := false
		for _, field := range allowedFields {
			if sortBy == field {
				allowed = true
				break
			}
		}

		if !allowed {
			s.badRequestResponse(c, "Invalid sort field", map[string]interface{}{
				"allowed_fields": allowedFields,
				"provided_field": sortBy,
			})
			return "", "", false
		}
	}

	return sortBy, sortOrder, true
}

// FilterQuery represents common filter parameters
type FilterQuery struct {
	Search string `form:"search" validate:"omitempty,max=100"`
	Status string `form:"status" validate:"omitempty"`
}

// GetFilterParams extracts and validates filter parameters
func (s *Server) GetFilterParams(c *gin.Context) (search, status string, valid bool) {
	var query FilterQuery

	if !s.bindQueryAndValidate(c, &query) {
		return "", "", false
	}

	return query.Search, query.Status, true
}

// parseIntParam parses an integer parameter from URL
func (s *Server) parseIntParam(c *gin.Context, paramName string) (int, bool) {
	paramStr := c.Param(paramName)
	if paramStr == "" {
		s.badRequestResponse(c, fmt.Sprintf("Missing parameter: %s", paramName), nil)
		return 0, false
	}

	value, err := strconv.Atoi(paramStr)
	if err != nil {
		s.badRequestResponse(c, fmt.Sprintf("Invalid parameter format: %s must be an integer", paramName), nil)
		return 0, false
	}

	return value, true
}

// parseUUIDParam validates a UUID parameter from URL
func (s *Server) parseUUIDParam(c *gin.Context, paramName string) (string, bool) {
	paramStr := c.Param(paramName)
	if paramStr == "" {
		s.badRequestResponse(c, fmt.Sprintf("Missing parameter: %s", paramName), nil)
		return "", false
	}

	// Basic UUID format validation (more thorough validation can be done with uuid package)
	if len(paramStr) != 36 || strings.Count(paramStr, "-") != 4 {
		s.badRequestResponse(c, fmt.Sprintf("Invalid UUID format: %s", paramName), nil)
		return "", false
	}

	return paramStr, true
	// uidStr, err := uuid.Parse(paramStr)
	// if err != nil {
	// 	return "", false
	// }

	// return uidStr.String(), true
}

// sanitizeInput performs basic input sanitization
func sanitizeInput(input string) string {
	// Remove leading/trailing whitespace
	input = strings.TrimSpace(input)

	// Basic HTML tag removal (for more comprehensive sanitization, use a proper library)
	input = strings.ReplaceAll(input, "<", "&lt;")
	input = strings.ReplaceAll(input, ">", "&gt;")

	return input
}

// sanitizeStringField sanitizes a string field in a struct
func sanitizeStringField(field *string) {
	if field != nil {
		*field = sanitizeInput(*field)
	}
}
