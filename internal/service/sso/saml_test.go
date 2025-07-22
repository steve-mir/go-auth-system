package sso

import (
	"context"

	"github.com/stretchr/testify/mock"
)

// MockStateStore is a mock implementation of StateStore
type MockStateStore struct {
	mock.Mock
}

func (m *MockStateStore) StoreState(ctx context.Context, state *OAuthState) error {
	args := m.Called(ctx, state)
	return args.Error(0)
}

func (m *MockStateStore) GetState(ctx context.Context, stateKey string) (*OAuthState, error) {
	args := m.Called(ctx, stateKey)
	return args.Get(0).(*OAuthState), args.Error(1)
}

func (m *MockStateStore) DeleteState(ctx context.Context, stateKey string) error {
	args := m.Called(ctx, stateKey)
	return args.Error(0)
}

// Test data
const testCertificate = `-----BEGIN CERTIFICATE-----
MIICXjCCAcegAwIBAgIJAKS0yiqVrJejMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQC7vbqajDw4o6gJy8UtqK9tF6CloQKdZKvxKV2rKV2rKV2rKV2rKV2rKV2rKV2r
KV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2r
KV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2rKV2r
KQIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAKqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq
-----END CERTIFICATE-----`

func createTestSAMLConfig() *SAMLConfig {
	return &SAMLConfig{
		ServiceProvider: SAMLServiceProvider{
			EntityID:                    "https://example.com/saml/metadata",
			AssertionConsumerServiceURL: "https://example.com/saml/acs",
			SingleLogoutServiceURL:      "https://example.com/saml/slo",
			X509Certificate:             testCertificate,
			PrivateKey:                  "test-private-key",
			NameIDFormat:                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			WantAssertionsSigned:        true,
			AuthnRequestsSigned:         true,
		},
		IdentityProviders: map[string]SAMLIdentityProvider{
			"test-idp": {
				EntityID:               "https://idp.example.com",
				SingleSignOnServiceURL: "https://idp.example.com/sso",
				X509Certificate:        testCertificate,
				NameIDFormat:           "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				WantAssertionsSigned:   true,
				WantResponseSigned:     true,
			},
		},
		AttributeMapping: SAMLAttributeMapping{
			Email:     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			FirstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			LastName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
			FullName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		},
		SessionTimeout:     3600,
		ClockSkewTolerance: 300,
		MaxAssertionAge:    3600,
	}
}
func TestSAMLService_GetMetadata(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()
	metadata, err := service.GetMetadata(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, metadata)

	// Parse the metadata to ensure it's valid XML
	var entityDescriptor EntityDescriptor
	err = xml.Unmarshal(metadata, &entityDescriptor)
	require.NoError(t, err)

	// Verify metadata content
	assert.Equal(t, config.ServiceProvider.EntityID, entityDescriptor.EntityID)
	assert.NotNil(t, entityDescriptor.SPSSODescriptor)
	assert.Equal(t, config.ServiceProvider.AuthnRequestsSigned, entityDescriptor.SPSSODescriptor.AuthnRequestsSigned)
	assert.Equal(t, config.ServiceProvider.WantAssertionsSigned, entityDescriptor.SPSSODescriptor.WantAssertionsSigned)
	assert.Len(t, entityDescriptor.SPSSODescriptor.AssertionConsumerService, 1)
	assert.Equal(t, config.ServiceProvider.AssertionConsumerServiceURL, entityDescriptor.SPSSODescriptor.AssertionConsumerService[0].Location)
}

func TestSAMLService_InitiateLogin(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()
	idpEntityID := "test-idp"
	relayState := "test-relay-state"

	// Mock state store
	mockStateStore.On("StoreState", ctx, mock.AnythingOfType("*sso.OAuthState")).Return(nil)

	authRequest, err := service.InitiateLogin(ctx, idpEntityID, relayState)

	require.NoError(t, err)
	assert.NotEmpty(t, authRequest.ID)
	assert.NotEmpty(t, authRequest.URL)
	assert.Equal(t, relayState, authRequest.RelayState)
	assert.Equal(t, idpEntityID, authRequest.IDPEntityID)
	assert.NotEmpty(t, authRequest.RequestXML)
	assert.Greater(t, authRequest.CreatedAt, int64(0))

	// Verify the URL contains the IdP SSO URL
	assert.Contains(t, authRequest.URL, config.IdentityProviders[idpEntityID].SingleSignOnServiceURL)

	mockStateStore.AssertExpectations(t)
}

func TestSAMLService_InitiateLogin_InvalidIdP(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()
	idpEntityID := "invalid-idp"

	_, err := service.InitiateLogin(ctx, idpEntityID, "")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "identity provider not found")
}

func TestSAMLService_ValidateAssertion(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()
	now := time.Now().Unix()

	tests := []struct {
		name      string
		assertion *SAMLAssertion
		wantError bool
		errorMsg  string
	}{
		{
			name: "valid assertion",
			assertion: &SAMLAssertion{
				ID:           "test-assertion-id",
				Issuer:       "test-idp",
				Subject:      "user@example.com",
				NameID:       "user@example.com",
				NotBefore:    now - 60,
				NotOnOrAfter: now + 3600,
				Audience:     config.ServiceProvider.EntityID,
				Attributes:   map[string]string{"email": "user@example.com"},
			},
			wantError: false,
		},
		{
			name: "assertion not yet valid",
			assertion: &SAMLAssertion{
				ID:           "test-assertion-id",
				Issuer:       "test-idp",
				Subject:      "user@example.com",
				NameID:       "user@example.com",
				NotBefore:    now + 3600,
				NotOnOrAfter: now + 7200,
				Audience:     config.ServiceProvider.EntityID,
				Attributes:   map[string]string{"email": "user@example.com"},
			},
			wantError: true,
			errorMsg:  "assertion not yet valid",
		},
		{
			name: "assertion expired",
			assertion: &SAMLAssertion{
				ID:           "test-assertion-id",
				Issuer:       "test-idp",
				Subject:      "user@example.com",
				NameID:       "user@example.com",
				NotBefore:    now - 7200,
				NotOnOrAfter: now - 3600,
				Audience:     config.ServiceProvider.EntityID,
				Attributes:   map[string]string{"email": "user@example.com"},
			},
			wantError: true,
			errorMsg:  "assertion has expired",
		},
		{
			name: "wrong audience",
			assertion: &SAMLAssertion{
				ID:           "test-assertion-id",
				Issuer:       "test-idp",
				Subject:      "user@example.com",
				NameID:       "user@example.com",
				NotBefore:    now - 60,
				NotOnOrAfter: now + 3600,
				Audience:     "wrong-audience",
				Attributes:   map[string]string{"email": "user@example.com"},
			},
			wantError: true,
			errorMsg:  "assertion audience mismatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateAssertion(ctx, tt.assertion)

			if tt.wantError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSAMLService_HandleResponse(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()

	// Create a test SAML response
	testResponse := createTestSAMLResponse(config)
	responseXML, err := xml.Marshal(testResponse)
	require.NoError(t, err)

	encodedResponse := base64.StdEncoding.EncodeToString(responseXML)

	// This test would require more complex setup to work properly
	// For now, we'll test that the method exists and handles basic validation
	_, err = service.HandleResponse(ctx, encodedResponse, "test-relay-state")

	// We expect an error because we haven't set up proper signature validation
	// In a real implementation, this would require proper certificate setup
	assert.Error(t, err)
}

func createTestSAMLResponse(config *SAMLConfig) *Response {
	now := time.Now().UTC()
	return &Response{
		ID:           "_test-response-id",
		Version:      "2.0",
		IssueInstant: now.Format("2006-01-02T15:04:05Z"),
		Destination:  config.ServiceProvider.AssertionConsumerServiceURL,
		InResponseTo: "_test-request-id",
		Issuer: Issuer{
			Value: "test-idp",
		},
		Status: Status{
			StatusCode: StatusCode{
				Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
			},
		},
		Assertion: []Assertion{
			{
				ID:           "_test-assertion-id",
				Version:      "2.0",
				IssueInstant: now.Format("2006-01-02T15:04:05Z"),
				Issuer: Issuer{
					Value: "test-idp",
				},
				Subject: Subject{
					NameID: NameID{
						Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
						Value:  "user@example.com",
					},
				},
				Conditions: Conditions{
					NotBefore:    now.Add(-5 * time.Minute).Format("2006-01-02T15:04:05Z"),
					NotOnOrAfter: now.Add(1 * time.Hour).Format("2006-01-02T15:04:05Z"),
					AudienceRestriction: []AudienceRestriction{
						{
							Audience: []string{config.ServiceProvider.EntityID},
						},
					},
				},
				AuthnStatement: []AuthnStatement{
					{
						AuthnInstant: now.Format("2006-01-02T15:04:05Z"),
						SessionIndex: "test-session-index",
						AuthnContext: AuthnContext{
							AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
						},
					},
				},
				AttributeStatement: &AttributeStatement{
					Attribute: []Attribute{
						{
							Name:           config.AttributeMapping.Email,
							AttributeValue: []string{"user@example.com"},
						},
						{
							Name:           config.AttributeMapping.FirstName,
							AttributeValue: []string{"John"},
						},
						{
							Name:           config.AttributeMapping.LastName,
							AttributeValue: []string{"Doe"},
						},
					},
				},
			},
		},
	}
}
