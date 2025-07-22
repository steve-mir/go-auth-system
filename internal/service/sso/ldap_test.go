package sso

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLDAPClient_BuildUserFilter(t *testing.T) {
	tests := []struct {
		name     string
		config   *LDAPConfig
		username string
		expected string
	}{
		{
			name: "custom user filter",
			config: &LDAPConfig{
				UserFilter: "(&(objectClass=person)(uid={username}))",
			},
			username: "testuser",
			expected: "(&(objectClass=person)(uid=testuser))",
		},
		{
			name: "default Active Directory filter",
			config: &LDAPConfig{
				Attributes: LDAPAttributeMapping{
					Username: "sAMAccountName",
				},
			},
			username: "testuser",
			expected: "(&(objectClass=user)(sAMAccountName=testuser))",
		},
		{
			name: "default filter with no username attribute",
			config: &LDAPConfig{
				Attributes: LDAPAttributeMapping{},
			},
			username: "testuser",
			expected: "(&(objectClass=user)(sAMAccountName=testuser))",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &LDAPClient{config: tt.config}
			result := client.buildUserFilter(tt.username)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLDAPClient_BuildUserAttributes(t *testing.T) {
	config := &LDAPConfig{
		Attributes: LDAPAttributeMapping{
			Username:    "sAMAccountName",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "displayName",
			Groups:      "memberOf",
			Enabled:     "userAccountControl",
		},
	}

	client := &LDAPClient{config: config}
	attributes := client.buildUserAttributes()

	expectedAttrs := []string{
		"dn", "sAMAccountName", "mail", "givenName", "sn",
		"displayName", "memberOf", "userAccountControl",
	}

	// Check that all expected attributes are present
	for _, expected := range expectedAttrs {
		assert.Contains(t, attributes, expected)
	}
}

func TestLDAPClient_IsUserEnabled(t *testing.T) {
	client := &LDAPClient{}

	tests := []struct {
		name     string
		value    string
		expected bool
	}{
		{"empty value", "", true},
		{"true value", "true", true},
		{"1 value", "1", true},
		{"active value", "active", true},
		{"enabled value", "enabled", true},
		{"false value", "false", false},
		{"0 value", "0", false},
		{"disabled value", "disabled", false},
		{"random value", "random", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.isUserEnabled(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLDAPClient_IsUserEnabledFromUAC(t *testing.T) {
	client := &LDAPClient{}

	tests := []struct {
		name     string
		uacValue string
		expected bool
	}{
		{"empty value", "", true},
		{"invalid value", "invalid", true},
		{"enabled account", "512", true},          // Normal account
		{"disabled account", "514", false},        // Disabled account (512 + 2)
		{"enabled with other flags", "544", true}, // Normal account with password not required
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.isUserEnabledFromUAC(tt.uacValue)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLDAPClient_ExtractGroupNameFromDN(t *testing.T) {
	client := &LDAPClient{}

	tests := []struct {
		name     string
		dn       string
		expected string
	}{
		{
			name:     "standard group DN",
			dn:       "CN=Domain Admins,CN=Users,DC=example,DC=com",
			expected: "Domain Admins",
		},
		{
			name:     "nested group DN",
			dn:       "CN=IT Team,OU=Groups,OU=IT,DC=company,DC=local",
			expected: "IT Team",
		},
		{
			name:     "no CN in DN",
			dn:       "OU=Groups,DC=example,DC=com",
			expected: "",
		},
		{
			name:     "empty DN",
			dn:       "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.extractGroupNameFromDN(tt.dn)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLDAPClient_RemoveDuplicateStrings(t *testing.T) {
	client := &LDAPClient{}

	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "all same",
			input:    []string{"a", "a", "a"},
			expected: []string{"a"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := client.removeDuplicateStrings(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLDAPConfig_DefaultValues(t *testing.T) {
	// Test that default LDAP configuration is properly set
	config := &LDAPConfig{
		Host:         "ldap.example.com",
		Port:         0, // Should default based on TLS setting
		BaseDN:       "DC=example,DC=com",
		BindDN:       "CN=service,CN=Users,DC=example,DC=com",
		BindPassword: "password",
		TLS:          false,
	}

	// Test default port assignment
	if config.Port == 0 {
		if config.TLS {
			config.Port = 636 // LDAPS
		} else {
			config.Port = 389 // LDAP
		}
	}

	assert.Equal(t, 389, config.Port)

	// Test with TLS
	config.TLS = true
	config.Port = 0
	if config.Port == 0 {
		if config.TLS {
			config.Port = 636 // LDAPS
		} else {
			config.Port = 389 // LDAP
		}
	}

	assert.Equal(t, 636, config.Port)
}

func TestLDAPResult_Validation(t *testing.T) {
	result := &LDAPResult{
		Username:   "testuser",
		Email:      "test@example.com",
		Name:       "Test User",
		FirstName:  "Test",
		LastName:   "User",
		Groups:     []string{"group1", "group2"},
		Attributes: map[string]string{"department": "IT"},
		IsNewUser:  true,
		DN:         "CN=Test User,CN=Users,DC=example,DC=com",
		LastSync:   time.Now().Unix(),
	}

	// Validate required fields
	assert.NotEmpty(t, result.Username)
	assert.NotEmpty(t, result.Email)
	assert.NotEmpty(t, result.DN)
	assert.True(t, result.IsNewUser)
	assert.Len(t, result.Groups, 2)
	assert.Contains(t, result.Attributes, "department")
}

func TestLDAPUser_Validation(t *testing.T) {
	user := &LDAPUser{
		DN:          "CN=Test User,CN=Users,DC=example,DC=com",
		Username:    "testuser",
		Email:       "test@example.com",
		FirstName:   "Test",
		LastName:    "User",
		DisplayName: "Test User",
		Groups:      []string{"group1", "group2"},
		Attributes:  map[string]string{"department": "IT"},
		Enabled:     true,
		LastLogon:   time.Now().Unix(),
	}

	// Validate required fields
	assert.NotEmpty(t, user.DN)
	assert.NotEmpty(t, user.Username)
	assert.NotEmpty(t, user.Email)
	assert.True(t, user.Enabled)
	assert.Len(t, user.Groups, 2)
}

func TestLDAPSyncResult_Validation(t *testing.T) {
	syncResult := &LDAPSyncResult{
		Username:   "testuser",
		Email:      "test@example.com",
		Name:       "Test User",
		Groups:     []string{"group1", "group2"},
		Attributes: map[string]string{"department": "IT"},
		Updated:    true,
		Changes:    []string{"updated email", "added to group"},
		SyncTime:   time.Now().Unix(),
	}

	// Validate sync result
	assert.NotEmpty(t, syncResult.Username)
	assert.NotEmpty(t, syncResult.Email)
	assert.True(t, syncResult.Updated)
	assert.Len(t, syncResult.Changes, 2)
	assert.Greater(t, syncResult.SyncTime, int64(0))
}

// Mock LDAP client for testing
type mockLDAPClient struct {
	users  map[string]*LDAPUser
	groups map[string][]string
}

func newMockLDAPClient() *mockLDAPClient {
	return &mockLDAPClient{
		users:  make(map[string]*LDAPUser),
		groups: make(map[string][]string),
	}
}

func (m *mockLDAPClient) addUser(username string, user *LDAPUser) {
	m.users[username] = user
}

func (m *mockLDAPClient) addUserGroups(username string, groups []string) {
	m.groups[username] = groups
}

func (m *mockLDAPClient) Authenticate(ctx context.Context, username, password string) (*LDAPResult, error) {
	user, exists := m.users[username]
	if !exists {
		return nil, NewLDAPUserNotFoundError(username)
	}

	if !user.Enabled {
		return nil, NewLDAPUserDisabledError(username)
	}

	// Mock successful authentication
	groups := m.groups[username]
	if groups == nil {
		groups = []string{}
	}

	return &LDAPResult{
		Username:   user.Username,
		Email:      user.Email,
		Name:       user.DisplayName,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		Groups:     groups,
		Attributes: user.Attributes,
		DN:         user.DN,
		LastSync:   time.Now().Unix(),
	}, nil
}

func (m *mockLDAPClient) SearchUser(ctx context.Context, username string) (*LDAPUser, error) {
	user, exists := m.users[username]
	if !exists {
		return nil, nil
	}
	return user, nil
}

func (m *mockLDAPClient) GetUserGroups(ctx context.Context, userDN string) ([]string, error) {
	// Find user by DN
	for username, user := range m.users {
		if user.DN == userDN {
			groups := m.groups[username]
			if groups == nil {
				return []string{}, nil
			}
			return groups, nil
		}
	}
	return []string{}, nil
}

func TestMockLDAPClient(t *testing.T) {
	ctx := context.Background()
	client := newMockLDAPClient()

	// Add test user
	testUser := &LDAPUser{
		DN:          "CN=Test User,CN=Users,DC=example,DC=com",
		Username:    "testuser",
		Email:       "test@example.com",
		FirstName:   "Test",
		LastName:    "User",
		DisplayName: "Test User",
		Enabled:     true,
		Attributes:  map[string]string{"department": "IT"},
	}

	client.addUser("testuser", testUser)
	client.addUserGroups("testuser", []string{"group1", "group2"})

	// Test authentication
	result, err := client.Authenticate(ctx, "testuser", "password")
	require.NoError(t, err)
	assert.Equal(t, "testuser", result.Username)
	assert.Equal(t, "test@example.com", result.Email)
	assert.Len(t, result.Groups, 2)

	// Test user search
	user, err := client.SearchUser(ctx, "testuser")
	require.NoError(t, err)
	assert.Equal(t, "testuser", user.Username)
	assert.True(t, user.Enabled)

	// Test get user groups
	groups, err := client.GetUserGroups(ctx, testUser.DN)
	require.NoError(t, err)
	assert.Len(t, groups, 2)
	assert.Contains(t, groups, "group1")
	assert.Contains(t, groups, "group2")

	// Test non-existent user
	_, err = client.Authenticate(ctx, "nonexistent", "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")

	// Test disabled user
	disabledUser := &LDAPUser{
		DN:          "CN=Disabled User,CN=Users,DC=example,DC=com",
		Username:    "disabled",
		Email:       "disabled@example.com",
		FirstName:   "Disabled",
		LastName:    "User",
		DisplayName: "Disabled User",
		Enabled:     false,
		Attributes:  map[string]string{},
	}

	client.addUser("disabled", disabledUser)

	_, err = client.Authenticate(ctx, "disabled", "password")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "disabled")
}
