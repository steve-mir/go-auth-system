package sso

import (
	"context"
	"fmt"
	"log"

	"github.com/stretchr/testify/mock"
)

// ExampleSAMLUsage demonstrates how to use the SAML service
func ExampleSAMLUsage() {
	// Create SAML configuration
	config := &SAMLConfig{
		ServiceProvider: SAMLServiceProvider{
			EntityID:                    "https://myapp.example.com/saml/metadata",
			AssertionConsumerServiceURL: "https://myapp.example.com/saml/acs",
			SingleLogoutServiceURL:      "https://myapp.example.com/saml/slo",
			X509Certificate:             "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
			PrivateKey:                  "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
			NameIDFormat:                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			WantAssertionsSigned:        true,
			AuthnRequestsSigned:         true,
		},
		IdentityProviders: map[string]SAMLIdentityProvider{
			"corporate-idp": {
				EntityID:               "https://idp.corporate.com",
				SingleSignOnServiceURL: "https://idp.corporate.com/sso",
				X509Certificate:        "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
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
			Groups:    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups",
			Roles:     "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
		},
		SessionTimeout:     3600, // 1 hour
		ClockSkewTolerance: 300,  // 5 minutes
		MaxAssertionAge:    3600, // 1 hour
	}

	// Create state store (you would use Redis or database in production)
	stateStore := &MockStateStore{}

	// Create SAML service
	samlService := NewSAMLService(config, stateStore)

	ctx := context.Background()

	// Example 1: Generate Service Provider metadata
	fmt.Println("=== SAML Service Provider Metadata ===")
	metadata, err := samlService.GetMetadata(ctx)
	if err != nil {
		log.Printf("Error generating metadata: %v", err)
		return
	}
	fmt.Printf("Metadata XML length: %d bytes\n", len(metadata))
	fmt.Printf("Metadata preview: %s...\n", string(metadata[:min(200, len(metadata))]))

	// Example 2: Initiate SAML login
	fmt.Println("\n=== Initiate SAML Login ===")
	idpEntityID := "corporate-idp"
	relayState := "return-to-dashboard"

	// Mock the state store for this example
	stateStore.On("StoreState", ctx, mock.AnythingOfType("*sso.OAuthState")).Return(nil)

	authRequest, err := samlService.InitiateLogin(ctx, idpEntityID, relayState)
	if err != nil {
		log.Printf("Error initiating login: %v", err)
		return
	}

	fmt.Printf("Auth Request ID: %s\n", authRequest.ID)
	fmt.Printf("Redirect URL: %s\n", authRequest.URL)
	fmt.Printf("Relay State: %s\n", authRequest.RelayState)
	fmt.Printf("Created At: %d\n", authRequest.CreatedAt)

	// Example 3: Validate SAML assertion
	fmt.Println("\n=== Validate SAML Assertion ===")
	testAssertion := &SAMLAssertion{
		ID:           "test-assertion-id",
		Issuer:       "corporate-idp",
		Subject:      "john.doe@corporate.com",
		NameID:       "john.doe@corporate.com",
		SessionIndex: "session-123",
		NotBefore:    1640995200, // Example timestamp
		NotOnOrAfter: 1641081600, // Example timestamp
		Audience:     config.ServiceProvider.EntityID,
		Attributes: map[string]string{
			config.AttributeMapping.Email:     "john.doe@corporate.com",
			config.AttributeMapping.FirstName: "John",
			config.AttributeMapping.LastName:  "Doe",
			config.AttributeMapping.FullName:  "John Doe",
			config.AttributeMapping.Groups:    "Developers,Managers",
		},
	}

	err = samlService.ValidateAssertion(ctx, testAssertion)
	if err != nil {
		log.Printf("Assertion validation failed: %v", err)
	} else {
		fmt.Println("Assertion validation successful!")
		fmt.Printf("User: %s (%s)\n", testAssertion.Attributes[config.AttributeMapping.FullName], testAssertion.NameID)
		fmt.Printf("Groups: %s\n", testAssertion.Attributes[config.AttributeMapping.Groups])
	}

	fmt.Println("\n=== SAML Integration Complete ===")
}

// ExampleSAMLWorkflow demonstrates a complete SAML authentication workflow
func ExampleSAMLWorkflow() {
	fmt.Println("=== Complete SAML Authentication Workflow ===")

	// Step 1: User visits protected resource
	fmt.Println("1. User visits protected resource")
	fmt.Println("   -> Redirect to SAML login")

	// Step 2: Generate SAML AuthnRequest
	fmt.Println("2. Generate SAML AuthnRequest")
	fmt.Println("   -> Create signed AuthnRequest XML")
	fmt.Println("   -> Redirect user to IdP with SAMLRequest parameter")

	// Step 3: User authenticates at IdP
	fmt.Println("3. User authenticates at Identity Provider")
	fmt.Println("   -> User enters credentials at IdP")
	fmt.Println("   -> IdP validates credentials")

	// Step 4: IdP sends SAML Response
	fmt.Println("4. IdP sends SAML Response")
	fmt.Println("   -> IdP creates signed SAML Response with assertion")
	fmt.Println("   -> POST to Assertion Consumer Service (ACS)")

	// Step 5: Validate SAML Response
	fmt.Println("5. Validate SAML Response")
	fmt.Println("   -> Verify signature")
	fmt.Println("   -> Validate assertion conditions")
	fmt.Println("   -> Extract user attributes")

	// Step 6: Create user session
	fmt.Println("6. Create user session")
	fmt.Println("   -> Create or update user account")
	fmt.Println("   -> Generate application session")
	fmt.Println("   -> Redirect to original resource or RelayState")

	fmt.Println("\n=== Workflow Complete ===")
}

// ExampleSAMLConfiguration shows different SAML configuration scenarios
func ExampleSAMLConfiguration() {
	fmt.Println("=== SAML Configuration Examples ===")

	// Example 1: Basic SAML configuration
	fmt.Println("1. Basic SAML Configuration:")
	basicConfig := &SAMLConfig{
		ServiceProvider: SAMLServiceProvider{
			EntityID:                    "https://app.example.com/saml",
			AssertionConsumerServiceURL: "https://app.example.com/saml/acs",
			NameIDFormat:                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
			WantAssertionsSigned:        true,
		},
		AttributeMapping: SAMLAttributeMapping{
			Email:     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			FirstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			LastName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
		},
		SessionTimeout:     1800, // 30 minutes
		ClockSkewTolerance: 180,  // 3 minutes
	}
	fmt.Printf("   Entity ID: %s\n", basicConfig.ServiceProvider.EntityID)
	fmt.Printf("   ACS URL: %s\n", basicConfig.ServiceProvider.AssertionConsumerServiceURL)

	// Example 2: Enterprise SAML configuration with multiple IdPs
	fmt.Println("\n2. Enterprise SAML Configuration:")
	enterpriseConfig := &SAMLConfig{
		ServiceProvider: SAMLServiceProvider{
			EntityID:                    "https://enterprise.example.com/saml",
			AssertionConsumerServiceURL: "https://enterprise.example.com/saml/acs",
			SingleLogoutServiceURL:      "https://enterprise.example.com/saml/slo",
			NameIDFormat:                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
			WantAssertionsSigned:        true,
			AuthnRequestsSigned:         true,
		},
		IdentityProviders: map[string]SAMLIdentityProvider{
			"azure-ad": {
				EntityID:               "https://sts.windows.net/tenant-id/",
				SingleSignOnServiceURL: "https://login.microsoftonline.com/tenant-id/saml2",
				NameIDFormat:           "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				WantAssertionsSigned:   true,
				WantResponseSigned:     true,
			},
			"okta": {
				EntityID:               "http://www.okta.com/exk1234567890",
				SingleSignOnServiceURL: "https://company.okta.com/app/company_app/exk1234567890/sso/saml",
				NameIDFormat:           "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
				WantAssertionsSigned:   true,
				WantResponseSigned:     false,
			},
		},
		AttributeMapping: SAMLAttributeMapping{
			Email:     "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
			FirstName: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
			LastName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
			FullName:  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
			Groups:    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/groups",
			Roles:     "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
		},
		SessionTimeout:     7200, // 2 hours
		ClockSkewTolerance: 300,  // 5 minutes
		MaxAssertionAge:    3600, // 1 hour
	}
	fmt.Printf("   Multiple IdPs: %d configured\n", len(enterpriseConfig.IdentityProviders))
	for name := range enterpriseConfig.IdentityProviders {
		fmt.Printf("   - %s\n", name)
	}

	fmt.Println("\n=== Configuration Examples Complete ===")
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
