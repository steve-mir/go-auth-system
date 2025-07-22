//go:build integration
// +build integration

package audit

import (
	"context"
	"log/slog"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/steve-mir/go-auth-system/internal/repository/postgres/db"
)

// AuditIntegrationTestSuite provides integration tests for the audit service
type AuditIntegrationTestSuite struct {
	suite.Suite
	db      *pgxpool.Pool
	queries *db.Queries
	service AuditService
	repo    AuditRepository
}

// SetupSuite sets up the test suite
func (suite *AuditIntegrationTestSuite) SetupSuite() {
	// This would typically connect to a test database
	// For now, we'll skip if no database URL is provided
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		suite.T().Skip("TEST_DATABASE_URL not set, skipping integration tests")
	}

	// Connect to test database
	pool, err := pgxpool.New(context.Background(), dbURL)
	require.NoError(suite.T(), err)

	suite.db = pool
	suite.queries = db.New(pool)

	// Create repository and service
	suite.repo = NewPostgresRepository(suite.queries)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	suite.service = NewService(suite.repo, logger)
}

// TearDownSuite cleans up the test suite
func (suite *AuditIntegrationTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// SetupTest sets up each test
func (suite *AuditIntegrationTestSuite) SetupTest() {
	// Clean up audit logs before each test
	ctx := context.Background()
	_, err := suite.db.Exec(ctx, "DELETE FROM audit_logs")
	require.NoError(suite.T(), err)
}

// TestLogEvent tests logging an audit event
func (suite *AuditIntegrationTestSuite) TestLogEvent() {
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

	err := suite.service.LogEvent(ctx, event)
	assert.NoError(suite.T(), err)

	// Verify the event was logged
	count, err := suite.service.CountAuditLogs(ctx)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(1), count)

	// Get the logged event
	logs, err := suite.service.GetRecentAuditLogs(ctx, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 1)

	loggedEvent := logs.AuditLogs[0]
	assert.Equal(suite.T(), userID, loggedEvent.UserID)
	assert.Equal(suite.T(), ActionUserLogin, loggedEvent.Action)
	assert.Equal(suite.T(), ResourceTypeUser, loggedEvent.ResourceType)
	assert.Equal(suite.T(), userID.String(), loggedEvent.ResourceID)
	assert.Equal(suite.T(), ipAddr, *loggedEvent.IPAddress)
	assert.Equal(suite.T(), "test-agent", loggedEvent.UserAgent)
	assert.Equal(suite.T(), true, loggedEvent.Metadata["success"])
	assert.Equal(suite.T(), "password", loggedEvent.Metadata["method"])
}

// TestGetUserAuditLogs tests retrieving audit logs for a specific user
func (suite *AuditIntegrationTestSuite) TestGetUserAuditLogs() {
	ctx := context.Background()
	userID1 := uuid.New()
	userID2 := uuid.New()

	// Log events for two different users
	events := []AuditEvent{
		{
			UserID: userID1,
			Action: ActionUserLogin,
		},
		{
			UserID: userID1,
			Action: ActionUserLogout,
		},
		{
			UserID: userID2,
			Action: ActionUserLogin,
		},
	}

	for _, event := range events {
		err := suite.service.LogEvent(ctx, event)
		require.NoError(suite.T(), err)
	}

	// Get logs for user1
	logs, err := suite.service.GetUserAuditLogs(ctx, userID1, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 2)
	assert.Equal(suite.T(), int64(2), logs.TotalCount)

	// Verify all logs belong to user1
	for _, log := range logs.AuditLogs {
		assert.Equal(suite.T(), userID1, log.UserID)
	}

	// Get logs for user2
	logs, err = suite.service.GetUserAuditLogs(ctx, userID2, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 1)
	assert.Equal(suite.T(), int64(1), logs.TotalCount)
	assert.Equal(suite.T(), userID2, logs.AuditLogs[0].UserID)
}

// TestGetAuditLogsByAction tests retrieving audit logs by action
func (suite *AuditIntegrationTestSuite) TestGetAuditLogsByAction() {
	ctx := context.Background()
	userID := uuid.New()

	// Log different types of events
	events := []AuditEvent{
		{
			UserID: userID,
			Action: ActionUserLogin,
		},
		{
			UserID: userID,
			Action: ActionUserLogin,
		},
		{
			UserID: userID,
			Action: ActionUserLogout,
		},
	}

	for _, event := range events {
		err := suite.service.LogEvent(ctx, event)
		require.NoError(suite.T(), err)
	}

	// Get login events
	logs, err := suite.service.GetAuditLogsByAction(ctx, ActionUserLogin, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 2)
	assert.Equal(suite.T(), int64(2), logs.TotalCount)

	// Verify all logs are login events
	for _, log := range logs.AuditLogs {
		assert.Equal(suite.T(), ActionUserLogin, log.Action)
	}

	// Get logout events
	logs, err = suite.service.GetAuditLogsByAction(ctx, ActionUserLogout, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 1)
	assert.Equal(suite.T(), int64(1), logs.TotalCount)
	assert.Equal(suite.T(), ActionUserLogout, logs.AuditLogs[0].Action)
}

// TestGetAuditLogsByTimeRange tests retrieving audit logs by time range
func (suite *AuditIntegrationTestSuite) TestGetAuditLogsByTimeRange() {
	ctx := context.Background()
	userID := uuid.New()

	// Log an event
	event := AuditEvent{
		UserID: userID,
		Action: ActionUserLogin,
	}

	err := suite.service.LogEvent(ctx, event)
	require.NoError(suite.T(), err)

	// Get logs from the last hour
	endTime := time.Now()
	startTime := endTime.Add(-1 * time.Hour)

	logs, err := suite.service.GetAuditLogsByTimeRange(ctx, startTime, endTime, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 1)

	// Get logs from a future time range (should be empty)
	futureStart := time.Now().Add(1 * time.Hour)
	futureEnd := time.Now().Add(2 * time.Hour)

	logs, err = suite.service.GetAuditLogsByTimeRange(ctx, futureStart, futureEnd, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 0)
}

// TestPagination tests pagination functionality
func (suite *AuditIntegrationTestSuite) TestPagination() {
	ctx := context.Background()
	userID := uuid.New()

	// Log 15 events
	for i := 0; i < 15; i++ {
		event := AuditEvent{
			UserID: userID,
			Action: ActionUserLogin,
			Metadata: map[string]interface{}{
				"sequence": i,
			},
		}
		err := suite.service.LogEvent(ctx, event)
		require.NoError(suite.T(), err)
	}

	// Get first page (10 items)
	logs, err := suite.service.GetUserAuditLogs(ctx, userID, GetAuditLogsRequest{
		Limit:  10,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 10)
	assert.Equal(suite.T(), int64(15), logs.TotalCount)

	// Get second page (5 items)
	logs, err = suite.service.GetUserAuditLogs(ctx, userID, GetAuditLogsRequest{
		Limit:  10,
		Offset: 10,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 5)
	assert.Equal(suite.T(), int64(15), logs.TotalCount)
}

// TestCleanupOldLogs tests cleanup functionality
func (suite *AuditIntegrationTestSuite) TestCleanupOldLogs() {
	ctx := context.Background()
	userID := uuid.New()

	// Log an event
	event := AuditEvent{
		UserID: userID,
		Action: ActionUserLogin,
	}

	err := suite.service.LogEvent(ctx, event)
	require.NoError(suite.T(), err)

	// Verify event exists
	count, err := suite.service.CountAuditLogs(ctx)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(1), count)

	// Cleanup logs older than now (should delete the log)
	err = suite.service.CleanupOldLogs(ctx, time.Now().Add(1*time.Minute))
	assert.NoError(suite.T(), err)

	// Verify log was deleted
	count, err = suite.service.CountAuditLogs(ctx)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(0), count)
}

// TestComplexMetadata tests logging events with complex metadata
func (suite *AuditIntegrationTestSuite) TestComplexMetadata() {
	ctx := context.Background()
	userID := uuid.New()

	complexMetadata := map[string]interface{}{
		"string_field":  "test_value",
		"number_field":  42,
		"boolean_field": true,
		"array_field":   []string{"item1", "item2", "item3"},
		"nested_object": map[string]interface{}{
			"nested_string": "nested_value",
			"nested_number": 123,
		},
		"timestamp": time.Now().Unix(),
	}

	event := AuditEvent{
		UserID:   userID,
		Action:   ActionUserLogin,
		Metadata: complexMetadata,
	}

	err := suite.service.LogEvent(ctx, event)
	assert.NoError(suite.T(), err)

	// Retrieve and verify the metadata
	logs, err := suite.service.GetUserAuditLogs(ctx, userID, GetAuditLogsRequest{
		Limit:  1,
		Offset: 0,
	})
	assert.NoError(suite.T(), err)
	assert.Len(suite.T(), logs.AuditLogs, 1)

	retrievedLog := logs.AuditLogs[0]
	assert.Equal(suite.T(), "test_value", retrievedLog.Metadata["string_field"])
	assert.Equal(suite.T(), float64(42), retrievedLog.Metadata["number_field"]) // JSON numbers are float64
	assert.Equal(suite.T(), true, retrievedLog.Metadata["boolean_field"])

	// Check nested object
	nestedObj, ok := retrievedLog.Metadata["nested_object"].(map[string]interface{})
	assert.True(suite.T(), ok)
	assert.Equal(suite.T(), "nested_value", nestedObj["nested_string"])
	assert.Equal(suite.T(), float64(123), nestedObj["nested_number"])
}

// TestConcurrentLogging tests concurrent audit logging
func (suite *AuditIntegrationTestSuite) TestConcurrentLogging() {
	ctx := context.Background()
	userID := uuid.New()

	// Number of concurrent goroutines
	numGoroutines := 10
	eventsPerGoroutine := 5

	// Channel to collect errors
	errChan := make(chan error, numGoroutines*eventsPerGoroutine)
	doneChan := make(chan bool, numGoroutines)

	// Start concurrent logging
	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer func() { doneChan <- true }()

			for j := 0; j < eventsPerGoroutine; j++ {
				event := AuditEvent{
					UserID: userID,
					Action: ActionUserLogin,
					Metadata: map[string]interface{}{
						"goroutine_id": goroutineID,
						"event_id":     j,
					},
				}

				if err := suite.service.LogEvent(ctx, event); err != nil {
					errChan <- err
				}
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-doneChan
	}
	close(errChan)

	// Check for errors
	var errors []error
	for err := range errChan {
		errors = append(errors, err)
	}
	assert.Empty(suite.T(), errors, "Expected no errors during concurrent logging")

	// Verify all events were logged
	expectedCount := int64(numGoroutines * eventsPerGoroutine)
	count, err := suite.service.CountUserAuditLogs(ctx, userID)
	assert.NoError(suite.T(), err)
	assert.Equal(suite.T(), expectedCount, count)
}

// TestAuditIntegrationSuite runs the integration test suite
func TestAuditIntegrationSuite(t *testing.T) {
	suite.Run(t, new(AuditIntegrationTestSuite))
}
