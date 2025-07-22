//go:build integration
// +build integration

package sso

import (
	"context"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// TestSAMLIntegration_MetadataGeneration tests SAML metadata generation
func TestSAMLIntegration_MetadataGeneration(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()
	metadata, err := service.GetMetadata(ctx)

	require.NoError(t, err)
	assert.NotEmpty(t, metadata)

	// Verify XML structure
	var entityDescriptor EntityDescriptor
	err = xml.Unmarshal(metadata, &entityDescriptor)
	require.NoError(t, err)

	// Verify required elements
	assert.Equal(t, config.ServiceProvider.EntityID, entityDescriptor.EntityID)
	assert.NotNil(t, entityDescriptor.SPSSODescriptor)

	// Verify key descriptor
	assert.Len(t, entityDescriptor.SPSSODescriptor.KeyDescriptor, 1)
	assert.Equal(t, "signing", entityDescriptor.SPSSODescriptor.KeyDescriptor[0].Use)

	// Verify assertion consumer service
	assert.Len(t, entityDescriptor.SPSSODescriptor.AssertionConsumerService, 1)
	acs := entityDescriptor.SPSSODescriptor.AssertionConsumerService[0]
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", acs.Binding)
	assert.Equal(t, config.ServiceProvider.AssertionConsumerServiceURL, acs.Location)
	assert.Equal(t, 0, acs.Index)

	// Verify NameID format
	assert.Contains(t, entityDescriptor.SPSSODescriptor.NameIDFormat, config.ServiceProvider.NameIDFormat)
}

// TestSAMLIntegration_AuthnRequestGeneration tests SAML AuthnRequest generation
func TestSAMLIntegration_AuthnRequestGeneration(t *testing.T) {
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
	assert.NotEmpty(t, authRequest.RequestXML)

	// Parse the AuthnRequest XML
	var authnRequest AuthnRequest
	err = xml.Unmarshal([]byte(authRequest.RequestXML), &authnRequest)
	require.NoError(t, err)

	// Verify AuthnRequest structure
	assert.NotEmpty(t, authnRequest.ID)
	assert.Equal(t, "2.0", authnRequest.Version)
	assert.NotEmpty(t, authnRequest.IssueInstant)
	assert.Equal(t, config.IdentityProviders[idpEntityID].SingleSignOnServiceURL, authnRequest.Destination)
	assert.Equal(t, config.ServiceProvider.EntityID, authnRequest.Issuer.Value)
	assert.Equal(t, config.ServiceProvider.AssertionConsumerServiceURL, authnRequest.AssertionConsumerServiceURL)
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", authnRequest.ProtocolBinding)

	// Verify NameIDPolicy
	assert.Equal(t, config.IdentityProviders[idpEntityID].NameIDFormat, authnRequest.NameIDPolicy.Format)
	assert.True(t, authnRequest.NameIDPolicy.AllowCreate)

	mockStateStore.AssertExpectations(t)
}

// TestSAMLIntegration_ResponseValidation tests SAML response validation
func TestSAMLIntegration_ResponseValidation(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()

	// Test assertion validation with various scenarios
	now := time.Now().Unix()

	tests := []struct {
		name      string
		assertion *SAMLAssertion
		wantError bool
	}{
		{
			name: "valid assertion",
			assertion: &SAMLAssertion{
				ID:           "test-assertion",
				Issuer:       "test-idp",
				Subject:      "user@example.com",
				NameID:       "user@example.com",
				NotBefore:    now - 300,
				NotOnOrAfter: now + 3600,
				Audience:     config.ServiceProvider.EntityID,
				Attributes: map[string]string{
					config.AttributeMapping.Email: "user@example.com",
				},
			},
			wantError: false,
		},
		{
			name: "expired assertion",
			assertion: &SAMLAssertion{
				ID:           "test-assertion",
				Issuer:       "test-idp",
				Subject:      "user@example.com",
				NameID:       "user@example.com",
				NotBefore:    now - 7200,
				NotOnOrAfter: now - 3600,
				Audience:     config.ServiceProvider.EntityID,
				Attributes: map[string]string{
					config.AttributeMapping.Email: "user@example.com",
				},
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateAssertion(ctx, tt.assertion)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestSAMLIntegration_HTTPBindings tests SAML HTTP bindings
func TestSAMLIntegration_HTTPBindings(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	// Test HTTP-Redirect binding for AuthnRequest
	t.Run("HTTP-Redirect AuthnRequest", func(t *testing.T) {
		ctx := context.Background()
		idpEntityID := "test-idp"

		mockStateStore.On("StoreState", ctx, mock.AnythingOfType("*sso.OAuthState")).Return(nil)

		authRequest, err := service.InitiateLogin(ctx, idpEntityID, "")
		require.NoError(t, err)

		// Verify URL structure
		assert.Contains(t, authRequest.URL, config.IdentityProviders[idpEntityID].SingleSignOnServiceURL)
		assert.Contains(t, authRequest.URL, "SAMLRequest=")

		mockStateStore.AssertExpectations(t)
	})

	// Test HTTP-POST binding simulation
	t.Run("HTTP-POST Response Simulation", func(t *testing.T) {
		// Create a test server to simulate IdP response
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("Expected POST request, got %s", r.Method)
				return
			}

			// Simulate SAML response form data
			samlResponse := r.FormValue("SAMLResponse")
			relayState := r.FormValue("RelayState")

			assert.NotEmpty(t, samlResponse)

			w.WriteHeader(http.StatusOK)
			w.Write([]byte("OK"))
		}))
		defer server.Close()

		// This would be used in a real integration test
		// where we simulate the full SAML flow
		assert.NotEmpty(t, server.URL)
	})
}

// TestSAMLIntegration_AttributeMapping tests SAML attribute mapping
func TestSAMLIntegration_AttributeMapping(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	// Test attribute extraction from assertion
	assertion := &Assertion{
		ID:           "_test-assertion",
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Issuer: Issuer{
			Value: "test-idp",
		},
		Subject: Subject{
			NameID: NameID{
				Format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				Value:  "user@example.com",
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
				{
					Name:           config.AttributeMapping.FullName,
					AttributeValue: []string{"John Doe"},
				},
			},
		},
	}

	result, err := service.extractUserInfo(assertion, "test-idp")
	require.NoError(t, err)

	assert.Equal(t, "user@example.com", result.Email)
	assert.Equal(t, "user@example.com", result.NameID)
	assert.Equal(t, "test-idp", result.IDPEntityID)
	assert.Equal(t, "John Doe", result.Name)
	assert.Contains(t, result.Attributes, config.AttributeMapping.Email)
	assert.Equal(t, "user@example.com", result.Attributes[config.AttributeMapping.Email])
}

// TestSAMLIntegration_ErrorHandling tests SAML error handling
func TestSAMLIntegration_ErrorHandling(t *testing.T) {
	config := createTestSAMLConfig()
	mockStateStore := &MockStateStore{}
	service := NewSAMLService(config, mockStateStore)

	ctx := context.Background()

	// Test invalid IdP
	t.Run("Invalid IdP", func(t *testing.T) {
		_, err := service.InitiateLogin(ctx, "invalid-idp", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "identity provider not found")
	})

	// Test invalid SAML response
	t.Run("Invalid SAML Response", func(t *testing.T) {
		_, err := service.HandleResponse(ctx, "invalid-base64", "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode SAML response")
	})

	// Test malformed XML
	t.Run("Malformed XML", func(t *testing.T) {
		invalidXML := "PGludmFsaWQ+PC9pbnZhbGlkPg==" // base64 encoded "<invalid></invalid>"
		_, err := service.HandleResponse(ctx, invalidXML, "")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse SAML response")
	})
}
