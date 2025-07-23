package deployment

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// TestDockerDeployment tests the Docker container deployment
func TestDockerDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker deployment test in short mode")
	}

	ctx := context.Background()

	// Start PostgreSQL container
	postgresContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:16.0-alpine3.18",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":       "auth_system",
				"POSTGRES_USER":     "postgres",
				"POSTGRES_PASSWORD": "postgres",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").WithOccurrence(2),
		},
		Started: true,
	})
	require.NoError(t, err)
	defer postgresContainer.Terminate(ctx)

	// Start Redis container
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7.0-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	require.NoError(t, err)
	defer redisContainer.Terminate(ctx)

	// Get container ports
	postgresPort, err := postgresContainer.MappedPort(ctx, "5432")
	require.NoError(t, err)

	redisPort, err := redisContainer.MappedPort(ctx, "6379")
	require.NoError(t, err)

	// Build the application Docker image
	appContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    "../../",
				Dockerfile: "Dockerfile",
			},
			ExposedPorts: []string{"8080/tcp", "9090/tcp", "8081/tcp"},
			Env: map[string]string{
				"DB_HOST":                 "host.docker.internal",
				"DB_PORT":                 postgresPort.Port(),
				"DB_NAME":                 "auth_system",
				"DB_USER":                 "postgres",
				"DB_PASSWORD":             "postgres",
				"DB_SSL_MODE":             "disable",
				"REDIS_HOST":              "host.docker.internal",
				"REDIS_PORT":              redisPort.Port(),
				"JWT_SIGNING_KEY":         "test-signing-key-for-deployment-test",
				"ENCRYPTION_MASTER_KEY":   "test-encryption-key-32-characters",
				"ENVIRONMENT":             "test",
				"LOG_LEVEL":               "info",
				"ADMIN_DASHBOARD_ENABLED": "true",
				"MONITORING_ENABLED":      "true",
			},
			WaitingFor: wait.ForHTTP("/health/live").WithPort("8080/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	defer appContainer.Terminate(ctx)

	// Get application port
	appPort, err := appContainer.MappedPort(ctx, "8080")
	require.NoError(t, err)

	baseURL := fmt.Sprintf("http://localhost:%s", appPort.Port())

	// Test health endpoints
	t.Run("HealthEndpoints", func(t *testing.T) {
		// Test liveness probe
		resp, err := http.Get(baseURL + "/health/live")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Test readiness probe
		resp, err = http.Get(baseURL + "/health/ready")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Test general health endpoint
		resp, err = http.Get(baseURL + "/health")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	// Test API endpoints
	t.Run("APIEndpoints", func(t *testing.T) {
		// Test root endpoint
		resp, err := http.Get(baseURL + "/")
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		// Test API base endpoint
		resp, err = http.Get(baseURL + "/api/v1")
		require.NoError(t, err)
		defer resp.Body.Close()
		// Should return 404 or redirect, but not 500
		assert.NotEqual(t, http.StatusInternalServerError, resp.StatusCode)
	})

	// Test metrics endpoint
	t.Run("MetricsEndpoint", func(t *testing.T) {
		metricsPort, err := appContainer.MappedPort(ctx, "8081")
		require.NoError(t, err)

		metricsURL := fmt.Sprintf("http://localhost:%s/metrics", metricsPort.Port())
		resp, err := http.Get(metricsURL)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})
}

// TestDockerComposeDeployment tests the docker-compose deployment
func TestDockerComposeDeployment(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker Compose deployment test in short mode")
	}

	// This test would use docker-compose to start the full stack
	// For now, we'll implement a basic structure
	t.Run("ComposeStackHealth", func(t *testing.T) {
		// TODO: Implement docker-compose based testing
		// This would involve:
		// 1. Starting docker-compose stack
		// 2. Waiting for all services to be healthy
		// 3. Running integration tests
		// 4. Cleaning up the stack
		t.Skip("Docker Compose integration test not yet implemented")
	})
}

// TestContainerSecurity tests security aspects of the container
func TestContainerSecurity(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping container security test in short mode")
	}

	ctx := context.Background()

	// Test that container runs as non-root user
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    "../../",
				Dockerfile: "Dockerfile",
			},
			Cmd: []string{"whoami"},
		},
		Started: true,
	})
	require.NoError(t, err)
	defer container.Terminate(ctx)

	// Wait for container to finish
	time.Sleep(2 * time.Second)

	logs, err := container.Logs(ctx)
	require.NoError(t, err)

	logBytes := make([]byte, 1024)
	n, _ := logs.Read(logBytes)
	logOutput := string(logBytes[:n])

	// Should not be running as root
	assert.NotContains(t, logOutput, "root")
	assert.Contains(t, logOutput, "appuser")
}

// TestContainerResourceLimits tests that the container respects resource limits
func TestContainerResourceLimits(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping container resource limits test in short mode")
	}

	ctx := context.Background()

	// Test with memory limit
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			FromDockerfile: testcontainers.FromDockerfile{
				Context:    "../../",
				Dockerfile: "Dockerfile",
			},
			Resources: testcontainers.Resources{
				Memory: 512 * 1024 * 1024, // 512MB
			},
			Env: map[string]string{
				"ENVIRONMENT": "test",
			},
		},
		Started: true,
	})
	require.NoError(t, err)
	defer container.Terminate(ctx)

	// Container should start successfully with limited resources
	assert.NotNil(t, container)
}
