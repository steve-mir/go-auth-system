package monitoring

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNewLogger(t *testing.T) {
	tests := []struct {
		name    string
		config  LoggerConfig
		wantErr bool
	}{
		{
			name: "valid json logger",
			config: LoggerConfig{
				Level:             LogLevelInfo,
				Format:            LogFormatJSON,
				Output:            "stdout",
				EnableTracing:     true,
				EnableCorrelation: true,
				ServiceName:       "test-service",
				ServiceVersion:    "1.0.0",
			},
			wantErr: false,
		},
		{
			name: "valid text logger",
			config: LoggerConfig{
				Level:             LogLevelDebug,
				Format:            LogFormatText,
				Output:            "stderr",
				EnableTracing:     false,
				EnableCorrelation: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLogger(tt.config)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLogger() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && logger == nil {
				t.Error("NewLogger() returned nil logger")
			}
		})
	}
}

func TestLogger_StartTrace(t *testing.T) {
	logger, err := NewLogger(LoggerConfig{
		Level:         LogLevelDebug,
		Format:        LogFormatJSON,
		Output:        "stdout",
		EnableTracing: true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	ctx := context.Background()
	operation := "test_operation"

	trace, newCtx := logger.StartTrace(ctx, operation)

	if trace == nil {
		t.Error("StartTrace() returned nil trace")
	}

	if trace.Operation != operation {
		t.Errorf("Expected operation %s, got %s", operation, trace.Operation)
	}

	if trace.TraceID == "" {
		t.Error("TraceID should not be empty")
	}

	if trace.SpanID == "" {
		t.Error("SpanID should not be empty")
	}

	if trace.Finished {
		t.Error("Trace should not be finished initially")
	}

	// Check context values
	if traceID := newCtx.Value("trace_id"); traceID == nil {
		t.Error("trace_id not found in context")
	}

	if spanID := newCtx.Value("span_id"); spanID == nil {
		t.Error("span_id not found in context")
	}
}

func TestLogger_FinishTrace(t *testing.T) {
	logger, err := NewLogger(LoggerConfig{
		Level:         LogLevelDebug,
		Format:        LogFormatJSON,
		Output:        "stdout",
		EnableTracing: true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	ctx := context.Background()
	trace, newCtx := logger.StartTrace(ctx, "test_operation")

	// Wait a bit to ensure duration is measurable
	time.Sleep(10 * time.Millisecond)

	// Test successful finish
	logger.FinishTrace(newCtx, trace, nil)

	if !trace.Finished {
		t.Error("Trace should be finished")
	}

	if trace.Duration == 0 {
		t.Error("Duration should be greater than 0")
	}

	// Test finish with error
	trace2, newCtx2 := logger.StartTrace(ctx, "test_operation_error")
	testErr := errors.New("test error")
	logger.FinishTrace(newCtx2, trace2, testErr)

	if !trace2.Finished {
		t.Error("Trace should be finished")
	}
}

func TestLogger_CreateCorrelation(t *testing.T) {
	logger, err := NewLogger(LoggerConfig{
		Level:             LogLevelInfo,
		Format:            LogFormatJSON,
		Output:            "stdout",
		EnableCorrelation: true,
	})
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	requestID := "req-123"
	sessionID := "sess-456"
	userID := "user-789"
	clientIP := "192.168.1.1"
	userAgent := "test-agent"

	correlation := logger.CreateCorrelation(requestID, sessionID, userID, clientIP, userAgent)

	if correlation == nil {
		t.Error("CreateCorrelation() returned nil")
	}

	if correlation.RequestID != requestID {
		t.Errorf("Expected RequestID %s, got %s", requestID, correlation.RequestID)
	}

	if correlation.SessionID != sessionID {
		t.Errorf("Expected SessionID %s, got %s", sessionID, correlation.SessionID)
	}

	if correlation.UserID != userID {
		t.Errorf("Expected UserID %s, got %s", userID, correlation.UserID)
	}

	if correlation.ClientIP != clientIP {
		t.Errorf("Expected ClientIP %s, got %s", clientIP, correlation.ClientIP)
	}

	if correlation.UserAgent != userAgent {
		t.Errorf("Expected UserAgent %s, got %s", userAgent, correlation.UserAgent)
	}

	if correlation.CorrelationID == "" {
		t.Error("CorrelationID should not be empty")
	}
}

func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()

	if id1 == "" {
		t.Error("generateID() returned empty string")
	}

	if id2 == "" {
		t.Error("generateID() returned empty string")
	}

	if id1 == id2 {
		t.Error("generateID() returned duplicate IDs")
	}

	// ID should be hex encoded (32 characters for 16 bytes)
	if len(id1) != 32 {
		t.Errorf("Expected ID length 32, got %d", len(id1))
	}
}
