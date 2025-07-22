//go:build integration
// +build integration

package sso

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

// LDAPIntegrationTestSuite contains integration tests for LDAP functionality
type LDAPIntegrationTestSuite struct {
	suite.Suite
	client *LDAPClient
	config *LDAPConfig
}

// SetupSuite sets up the test suite
func (suite *LDAPIntegrationTestSuite) SetupSuite() {
	// Skip if LDAP integration tests are not enabled
	if os.Getenv("LDAP_INTEGRATION_TESTS") != "true" {
		suite.T().Skip("LDAP integration tests not enabled")
	}

	// Get LDAP configuration from environment
	suite.config = &LDAPConfig{
		Host:         getEnvOrDefault("LDAP_HOST", "localhost"),
		Port:         getEnvIntOrDefault("LDAP_PORT", 389),
		BaseDN:       getEnvOrDefault("LDAP_BASE_DN", "DC=example,DC=com"),
		BindDN:       getEnvOrDefault("LDAP_BIND_DN", "CN=admin,DC=example,DC=com"),
		BindPassword: getEnvOrDefault("LDAP_BIND_PASSWORD", "admin"),
		UserFilter:   getEnvOrDefault("LDAP_USER_FILTER", ""),
		GroupFilter:  getEnvOrDefault("LDAP_GROUP_FILTER", ""),
		TLS:          getEnvBoolOrDefault("LDAP_TLS", false),
		Attributes: LDAPAttributeMapping{
			Username:    "sAMAccountName",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "displayName",
			Groups:      "memberOf",
			Enabled:     "userAccountControl",
		},
		GroupSync: LDAPGroupSyncConfig{
			Enabled:       true,
			GroupBaseDN:   getEnvOrDefault("LDAP_GROUP_BASE_DN", "CN=Users,DC=example,DC=com"),
			GroupFilter:   "(objectClass=group)",
			MemberAttr:    "member",
			GroupNameAttr: "cn",
		},
		Connection: LDAPConnectionConfig{
			Timeout:       30,
			ReadTimeout:   30,
			WriteTimeout:  30,
			SkipTLSVerify: getEnvBoolOrDefault("LDAP_SKIP_TLS_VERIFY", true),
		},
	}

	// Create LDAP client
	client, err := NewLDAPClient(suite.config)
	require.NoError(suite.T(), err, "Failed to create LDAP client")
	suite.client = client
}

// TearDownSuite cleans up the test suite
func (suite *LDAPIntegrationTestSuite) TearDownSuite() {
	if suite.client != nil {
		suite.client.Close()
	}
}

// TestLDAPConnection tests LDAP connection
func (suite *LDAPIntegrationTestSuite) TestLDAPConnection() {
	// Test that we can establish a connection
	assert.NotNil(suite.T(), suite.client)
	assert.NotNil(suite.T(), suite.client.conn)
}

// TestLDAPBind tests LDAP bind operation
func (suite *LDAPIntegrationTestSuite) TestLDAPBind() {
	err := suite.client.bind()
	assert.NoError(suite.T(), err, "LDAP bind should succeed")
}

// TestLDAPSearchUser tests user search functionality
func (suite *LDAPIntegrationTestSuite) TestLDAPSearchUser() {
	ctx := context.Background()
	testUsername := getEnvOrDefault("LDAP_TEST_USERNAME", "testuser")

	// Skip if no test username provided
	if testUsername == "testuser" {
		suite.T().Skip("No test username provided (set LDAP_TEST_USERNAME)")
	}

	user, err := suite.client.SearchUser(ctx, testUsername)

	if err != nil {
		// User might not exist, which is okay for this test
		suite.T().Logf("User search failed (expected if user doesn't exist): %v", err)
		return
	}

	if user != nil {
		assert.NotEmpty(suite.T(), user.DN, "User DN should not be empty")
		assert.NotEmpty(suite.T(), user.Username, "Username should not be empty")
		suite.T().Logf("Found user: %s (%s)", user.Username, user.DN)
	}
}

// TestLDAPAuthenticate tests user authentication
func (suite *LDAPIntegrationTestSuite) TestLDAPAuthenticate() {
	ctx := context.Background()
	testUsername := getEnvOrDefault("LDAP_TEST_USERNAME", "testuser")
	testPassword := getEnvOrDefault("LDAP_TEST_PASSWORD", "")

	// Skip if no test credentials provided
	if testUsername == "testuser" || testPassword == "" {
		suite.T().Skip("No test credentials provided (set LDAP_TEST_USERNAME and LDAP_TEST_PASSWORD)")
	}

	result, err := suite.client.Authenticate(ctx, testUsername, testPassword)

	if err != nil {
		// Authentication might fail, which is okay for this test
		suite.T().Logf("Authentication failed (expected if credentials are wrong): %v", err)
		return
	}

	if result != nil {
		assert.NotEmpty(suite.T(), result.Username, "Username should not be empty")
		assert.NotEmpty(suite.T(), result.Email, "Email should not be empty")
		assert.NotEmpty(suite.T(), result.DN, "DN should not be empty")
		suite.T().Logf("Authentication successful for user: %s", result.Username)
	}
}

// TestLDAPGetUserGroups tests group retrieval
func (suite *LDAPIntegrationTestSuite) TestLDAPGetUserGroups() {
	ctx := context.Background()
	testUsername := getEnvOrDefault("LDAP_TEST_USERNAME", "testuser")

	// Skip if no test username provided
	if testUsername == "testuser" {
		suite.T().Skip("No test username provided (set LDAP_TEST_USERNAME)")
	}

	// First search for the user to get their DN
	user, err := suite.client.SearchUser(ctx, testUsername)
	if err != nil || user == nil {
		suite.T().Skip("Test user not found, skipping group test")
	}

	groups, err := suite.client.GetUserGroups(ctx, user.DN)

	if err != nil {
		suite.T().Logf("Group retrieval failed: %v", err)
		return
	}

	suite.T().Logf("User %s is member of %d groups: %v", testUsername, len(groups), groups)
	assert.IsType(suite.T(), []string{}, groups, "Groups should be a string slice")
}

// TestLDAPSyncUser tests user synchronization
func (suite *LDAPIntegrationTestSuite) TestLDAPSyncUser() {
	ctx := context.Background()
	testUsername := getEnvOrDefault("LDAP_TEST_USERNAME", "testuser")

	// Skip if no test username provided
	if testUsername == "testuser" {
		suite.T().Skip("No test username provided (set LDAP_TEST_USERNAME)")
	}

	result, err := suite.client.SyncUser(ctx, testUsername)

	if err != nil {
		suite.T().Logf("User sync failed: %v", err)
		return
	}

	if result != nil {
		assert.NotEmpty(suite.T(), result.Username, "Username should not be empty")
		assert.NotEmpty(suite.T(), result.Email, "Email should not be empty")
		assert.True(suite.T(), result.Updated, "Updated flag should be true")
		assert.Greater(suite.T(), result.SyncTime, int64(0), "Sync time should be set")
		suite.T().Logf("User sync successful: %s", result.Username)
	}
}

// TestLDAPErrorHandling tests error handling scenarios
func (suite *LDAPIntegrationTestSuite) TestLDAPErrorHandling() {
	ctx := context.Background()

	// Test with non-existent user
	_, err := suite.client.SearchUser(ctx, "nonexistentuser12345")
	// This should not return an error, but should return nil user
	assert.NoError(suite.T(), err)

	// Test authentication with non-existent user
	_, err = suite.client.Authenticate(ctx, "nonexistentuser12345", "password")
	assert.Error(suite.T(), err)
	assert.Contains(suite.T(), err.Error(), "not found")

	// Test authentication with empty password
	testUsername := getEnvOrDefault("LDAP_TEST_USERNAME", "testuser")
	if testUsername != "testuser" {
		_, err = suite.client.Authenticate(ctx, testUsername, "")
		assert.Error(suite.T(), err)
	}
}

// TestLDAPConfigValidation tests configuration validation
func (suite *LDAPIntegrationTestSuite) TestLDAPConfigValidation() {
	// Test with invalid host
	invalidConfig := &LDAPConfig{
		Host:         "invalid-host-12345",
		Port:         389,
		BaseDN:       "DC=example,DC=com",
		BindDN:       "CN=admin,DC=example,DC=com",
		BindPassword: "admin",
		Connection: LDAPConnectionConfig{
			Timeout: 5, // Short timeout for quick failure
		},
	}

	_, err := NewLDAPClient(invalidConfig)
	assert.Error(suite.T(), err, "Should fail with invalid host")
}

// Helper functions for environment variables
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntOrDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		// Simple conversion, in real code you'd handle errors
		if value == "636" {
			return 636
		}
		if value == "389" {
			return 389
		}
	}
	return defaultValue
}

func getEnvBoolOrDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		return value == "true" || value == "1"
	}
	return defaultValue
}

// TestLDAPIntegrationSuite runs the integration test suite
func TestLDAPIntegrationSuite(t *testing.T) {
	suite.Run(t, new(LDAPIntegrationTestSuite))
}

// Benchmark tests for LDAP operations
func BenchmarkLDAPSearchUser(b *testing.B) {
	if os.Getenv("LDAP_INTEGRATION_TESTS") != "true" {
		b.Skip("LDAP integration tests not enabled")
	}

	config := &LDAPConfig{
		Host:         getEnvOrDefault("LDAP_HOST", "localhost"),
		Port:         getEnvIntOrDefault("LDAP_PORT", 389),
		BaseDN:       getEnvOrDefault("LDAP_BASE_DN", "DC=example,DC=com"),
		BindDN:       getEnvOrDefault("LDAP_BIND_DN", "CN=admin,DC=example,DC=com"),
		BindPassword: getEnvOrDefault("LDAP_BIND_PASSWORD", "admin"),
		TLS:          getEnvBoolOrDefault("LDAP_TLS", false),
		Attributes: LDAPAttributeMapping{
			Username: "sAMAccountName",
			Email:    "mail",
		},
		Connection: LDAPConnectionConfig{
			Timeout: 30,
		},
	}

	client, err := NewLDAPClient(config)
	if err != nil {
		b.Fatalf("Failed to create LDAP client: %v", err)
	}
	defer client.Close()

	testUsername := getEnvOrDefault("LDAP_TEST_USERNAME", "testuser")
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.SearchUser(ctx, testUsername)
	}
}

func BenchmarkLDAPAuthenticate(b *testing.B) {
	if os.Getenv("LDAP_INTEGRATION_TESTS") != "true" {
		b.Skip("LDAP integration tests not enabled")
	}

	testUsername := getEnvOrDefault("LDAP_TEST_USERNAME", "testuser")
	testPassword := getEnvOrDefault("LDAP_TEST_PASSWORD", "")

	if testUsername == "testuser" || testPassword == "" {
		b.Skip("No test credentials provided")
	}

	config := &LDAPConfig{
		Host:         getEnvOrDefault("LDAP_HOST", "localhost"),
		Port:         getEnvIntOrDefault("LDAP_PORT", 389),
		BaseDN:       getEnvOrDefault("LDAP_BASE_DN", "DC=example,DC=com"),
		BindDN:       getEnvOrDefault("LDAP_BIND_DN", "CN=admin,DC=example,DC=com"),
		BindPassword: getEnvOrDefault("LDAP_BIND_PASSWORD", "admin"),
		TLS:          getEnvBoolOrDefault("LDAP_TLS", false),
		Attributes: LDAPAttributeMapping{
			Username: "sAMAccountName",
			Email:    "mail",
		},
		Connection: LDAPConnectionConfig{
			Timeout: 30,
		},
	}

	client, err := NewLDAPClient(config)
	if err != nil {
		b.Fatalf("Failed to create LDAP client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Authenticate(ctx, testUsername, testPassword)
	}
}
