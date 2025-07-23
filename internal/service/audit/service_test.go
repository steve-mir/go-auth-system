package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockAuditRepository is a mock implementation of AuditRepository
type MockAuditRepository struct {
	mock.Mock
}

func (m *MockAuditRepository) CreateAuditLog(ctx context.Context, params CreateAuditLogParams) (*AuditLog, error) {
	args := m.Called(ctx, params)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuditLog), args.Error(1)
}

func (m *MockAuditRepository) GetAuditLogByID(ctx context.Context, id uuid.UUID) (*AuditLog, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*AuditLog), args.Error(1)
}

func (m *MockAuditRepository) GetUserAuditLogs(ctx context.Context, userID uuid.UUID, limit, offset int32) ([]*AuditLog, error) {
	args := m.Called(ctx, userID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*AuditLog), args.Error(1)
}

func (m *MockAuditRepository) GetAuditLogsByAction(ctx context.Context, action string, limit, offset int32) ([]*AuditLog, error) {
	args := m.Called(ctx, action, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*AuditLog), args.Error(1)
}

func (m *MockAuditRepository) GetAuditLogsByResource(ctx context.Context, resourceType, resourceID string, limit, offset int32) ([]*AuditLog, error) {
	args := m.Called(ctx, resourceType, resourceID, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*AuditLog), args.Error(1)
}

func (m *MockAuditRepository) GetAuditLogsByTimeRange(ctx context.Context, startTime, endTime time.Time, limit, offset int32) ([]*AuditLog, error) {
	args := m.Called(ctx, startTime, endTime, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*AuditLog), args.Error(1)
}

func (m *MockAuditRepository) GetRecentAuditLogs(ctx context.Context, limit, offset int32) ([]*AuditLog, error) {
	args := m.Called(ctx, limit, offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*AuditLog), args.Error(1)
}

func (m *MockAuditRepository) CountAuditLogs(ctx context.Context) (int64, error) {
	args := m.Called(ctx)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditRepository) CountUserAuditLogs(ctx context.Context, userID uuid.UUID) (int64, error) {
	args := m.Called(ctx, userID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditRepository) CountAuditLogsByAction(ctx context.Context, action string) (int64, error) {
	args := m.Called(ctx, action)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockAuditRepository) DeleteOldAuditLogs(ctx context.Context, olderThan time.Time) error {
	args := m.Called(ctx, olderThan)
	return args.Error(0)
}

func TestNewService(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	service := NewService(mockRepo, logger)

	assert.NotNil(t, service)
	// assert.IsType(t, &service{}, service)
}

func TestService_LogEvent(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	userID := uuid.New()
	ipAddr := netip.MustParseAddr("192.168.1.1")

	event := AuditEvent{
		UserID:       userID,
		Action:       ActionUserLogin,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    &ipAddr,
		UserAgent:    "test-agent",
		Metadata: map[string]interface{}{
			"success": true,
			"method":  "password",
		},
	}

	expectedAuditLog := &AuditLog{
		ID:           uuid.New(),
		UserID:       userID,
		Action:       ActionUserLogin,
		ResourceType: ResourceTypeUser,
		ResourceID:   userID.String(),
		IPAddress:    &ipAddr,
		UserAgent:    "test-agent",
		Metadata:     event.Metadata,
		Timestamp:    time.Now(),
	}

	mockRepo.On("CreateAuditLog", ctx, mock.MatchedBy(func(params CreateAuditLogParams) bool {
		return params.UserID == userID &&
			params.Action == ActionUserLogin &&
			params.ResourceType == ResourceTypeUser &&
			params.ResourceID == userID.String()
	})).Return(expectedAuditLog, nil)

	err := service.LogEvent(ctx, event)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestService_LogEvent_MetadataError(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	userID := uuid.New()

	// Create an event with metadata that can't be marshaled to JSON
	event := AuditEvent{
		UserID: userID,
		Action: ActionUserLogin,
		Metadata: map[string]interface{}{
			"invalid": make(chan int), // channels can't be marshaled to JSON
		},
	}

	err := service.LogEvent(ctx, event)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal metadata")
}

func TestService_GetUserAuditLogs(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	userID := uuid.New()
	req := GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	}

	expectedLogs := []*AuditLog{
		{
			ID:        uuid.New(),
			UserID:    userID,
			Action:    ActionUserLogin,
			Timestamp: time.Now(),
		},
	}

	mockRepo.On("GetUserAuditLogs", ctx, userID, int32(10), int32(0)).Return(expectedLogs, nil)
	mockRepo.On("CountUserAuditLogs", ctx, userID).Return(int64(1), nil)

	response, err := service.GetUserAuditLogs(ctx, userID, req)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, expectedLogs, response.AuditLogs)
	assert.Equal(t, int64(1), response.TotalCount)
	assert.Equal(t, int32(10), response.Limit)
	assert.Equal(t, int32(0), response.Offset)
	mockRepo.AssertExpectations(t)
}

func TestService_GetUserAuditLogs_InvalidPagination(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	userID := uuid.New()

	tests := []struct {
		name string
		req  GetAuditLogsRequest
	}{
		{
			name: "zero limit",
			req: GetAuditLogsRequest{
				Limit:  0,
				Offset: 0,
			},
		},
		{
			name: "negative limit",
			req: GetAuditLogsRequest{
				Limit:  -1,
				Offset: 0,
			},
		},
		{
			name: "limit too large",
			req: GetAuditLogsRequest{
				Limit:  1001,
				Offset: 0,
			},
		},
		{
			name: "negative offset",
			req: GetAuditLogsRequest{
				Limit:  10,
				Offset: -1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := service.GetUserAuditLogs(ctx, userID, tt.req)

			assert.Error(t, err)
			assert.Nil(t, response)
		})
	}
}

func TestService_GetAuditLogsByAction(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	action := ActionUserLogin
	req := GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	}

	expectedLogs := []*AuditLog{
		{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Action:    action,
			Timestamp: time.Now(),
		},
	}

	mockRepo.On("GetAuditLogsByAction", ctx, action, int32(10), int32(0)).Return(expectedLogs, nil)
	mockRepo.On("CountAuditLogsByAction", ctx, action).Return(int64(1), nil)

	response, err := service.GetAuditLogsByAction(ctx, action, req)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, expectedLogs, response.AuditLogs)
	assert.Equal(t, int64(1), response.TotalCount)
	mockRepo.AssertExpectations(t)
}

func TestService_GetAuditLogsByTimeRange(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	startTime := time.Now().Add(-24 * time.Hour)
	endTime := time.Now()
	req := GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	}

	expectedLogs := []*AuditLog{
		{
			ID:        uuid.New(),
			UserID:    uuid.New(),
			Action:    ActionUserLogin,
			Timestamp: time.Now().Add(-1 * time.Hour),
		},
	}

	mockRepo.On("GetAuditLogsByTimeRange", ctx, startTime, endTime, int32(10), int32(0)).Return(expectedLogs, nil)
	mockRepo.On("CountAuditLogs", ctx).Return(int64(1), nil)

	response, err := service.GetAuditLogsByTimeRange(ctx, startTime, endTime, req)

	assert.NoError(t, err)
	assert.NotNil(t, response)
	assert.Equal(t, expectedLogs, response.AuditLogs)
	mockRepo.AssertExpectations(t)
}

func TestService_GetAuditLogsByTimeRange_InvalidRange(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	startTime := time.Now()
	endTime := time.Now().Add(-1 * time.Hour) // end time before start time
	req := GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	}

	response, err := service.GetAuditLogsByTimeRange(ctx, startTime, endTime, req)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "start time cannot be after end time")
}

func TestService_GetAuditLogByID(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	auditLogID := uuid.New()

	expectedLog := &AuditLog{
		ID:        auditLogID,
		UserID:    uuid.New(),
		Action:    ActionUserLogin,
		Timestamp: time.Now(),
	}

	mockRepo.On("GetAuditLogByID", ctx, auditLogID).Return(expectedLog, nil)

	result, err := service.GetAuditLogByID(ctx, auditLogID)

	assert.NoError(t, err)
	assert.Equal(t, expectedLog, result)
	mockRepo.AssertExpectations(t)
}

func TestService_CountAuditLogs(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	expectedCount := int64(100)

	mockRepo.On("CountAuditLogs", ctx).Return(expectedCount, nil)

	count, err := service.CountAuditLogs(ctx)

	assert.NoError(t, err)
	assert.Equal(t, expectedCount, count)
	mockRepo.AssertExpectations(t)
}

func TestService_CleanupOldLogs(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger)

	ctx := context.Background()
	olderThan := time.Now().Add(-30 * 24 * time.Hour) // 30 days ago

	mockRepo.On("DeleteOldAuditLogs", ctx, olderThan).Return(nil)

	err := service.CleanupOldLogs(ctx, olderThan)

	assert.NoError(t, err)
	mockRepo.AssertExpectations(t)
}

func TestAuditEvent_ToJSON(t *testing.T) {
	tests := []struct {
		name     string
		event    AuditEvent
		expected string
	}{
		{
			name: "with metadata",
			event: AuditEvent{
				Metadata: map[string]interface{}{
					"key1": "value1",
					"key2": 123,
				},
			},
			expected: `{"key1":"value1","key2":123}`,
		},
		{
			name:     "nil metadata",
			event:    AuditEvent{},
			expected: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.event.ToJSON()

			require.NoError(t, err)

			// Parse both JSON strings to compare content
			var expectedMap, resultMap map[string]interface{}
			err = json.Unmarshal([]byte(tt.expected), &expectedMap)
			require.NoError(t, err)
			err = json.Unmarshal(result, &resultMap)
			require.NoError(t, err)

			assert.Equal(t, expectedMap, resultMap)
		})
	}
}

func TestAuditLog_FromJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		expected map[string]interface{}
	}{
		{
			name:     "valid JSON",
			jsonData: `{"key1":"value1","key2":123}`,
			expected: map[string]interface{}{
				"key1": "value1",
				"key2": float64(123), // JSON numbers are parsed as float64
			},
		},
		{
			name:     "empty JSON",
			jsonData: `{}`,
			expected: map[string]interface{}{},
		},
		{
			name:     "empty data",
			jsonData: "",
			expected: map[string]interface{}{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auditLog := &AuditLog{}
			err := auditLog.FromJSON(json.RawMessage(tt.jsonData))

			require.NoError(t, err)
			assert.Equal(t, tt.expected, auditLog.Metadata)
		})
	}
}

func TestService_validatePaginationRequest(t *testing.T) {
	mockRepo := &MockAuditRepository{}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewService(mockRepo, logger).(*service)

	tests := []struct {
		name    string
		req     GetAuditLogsRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: GetAuditLogsRequest{
				Limit:  10,
				Offset: 0,
			},
			wantErr: false,
		},
		{
			name: "zero limit",
			req: GetAuditLogsRequest{
				Limit:  0,
				Offset: 0,
			},
			wantErr: true,
		},
		{
			name: "negative limit",
			req: GetAuditLogsRequest{
				Limit:  -1,
				Offset: 0,
			},
			wantErr: true,
		},
		{
			name: "limit too large",
			req: GetAuditLogsRequest{
				Limit:  1001,
				Offset: 0,
			},
			wantErr: true,
		},
		{
			name: "negative offset",
			req: GetAuditLogsRequest{
				Limit:  10,
				Offset: -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validatePaginationRequest(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
