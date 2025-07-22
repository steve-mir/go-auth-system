package sso

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// SAMLService handles SAML 2.0 Service Provider operations
type SAMLService struct {
	config     *SAMLConfig
	stateStore StateStore
}

// NewSAMLService creates a new SAML service
func NewSAMLService(config *SAMLConfig, stateStore StateStore) *SAMLService {
	return &SAMLService{
		config:     config,
		stateStore: stateStore,
	}
}

// GetMetadata generates SAML Service Provider metadata
func (s *SAMLService) GetMetadata(ctx context.Context) ([]byte, error) {
	sp := s.config.ServiceProvider

	metadata := &EntityDescriptor{
		XMLName:  xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "EntityDescriptor"},
		EntityID: sp.EntityID,
		SPSSODescriptor: &SPSSODescriptor{
			XMLName:                    xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:metadata", Local: "SPSSODescriptor"},
			AuthnRequestsSigned:        sp.AuthnRequestsSigned,
			WantAssertionsSigned:       sp.WantAssertionsSigned,
			ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			KeyDescriptor: []KeyDescriptor{
				{
					Use: "signing",
					KeyInfo: KeyInfo{
						X509Data: X509Data{
							X509Certificate: strings.ReplaceAll(sp.X509Certificate, "\n", ""),
						},
					},
				},
			},
			NameIDFormat: []string{
				sp.NameIDFormat,
			},
			AssertionConsumerService: []AssertionConsumerService{
				{
					Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
					Location: sp.AssertionConsumerServiceURL,
					Index:    0,
				},
			},
		},
	}

	if sp.SingleLogoutServiceURL != "" {
		metadata.SPSSODescriptor.SingleLogoutService = []SingleLogoutService{
			{
				Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
				Location: sp.SingleLogoutServiceURL,
			},
		}
	}

	xmlData, err := xml.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal metadata: %w", err)
	}

	// Add XML declaration
	result := []byte(xml.Header + string(xmlData))
	return result, nil
}

// InitiateLogin creates a SAML authentication request
func (s *SAMLService) InitiateLogin(ctx context.Context, idpEntityID string, relayState string) (*SAMLAuthRequest, error) {
	idp, exists := s.config.IdentityProviders[idpEntityID]
	if !exists {
		return nil, fmt.Errorf("identity provider not found: %s", idpEntityID)
	}

	// Generate request ID
	requestID := "_" + uuid.New().String()

	// Create AuthnRequest
	authnRequest := &AuthnRequest{
		XMLName:      xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:protocol", Local: "AuthnRequest"},
		ID:           requestID,
		Version:      "2.0",
		IssueInstant: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		Destination:  idp.SingleSignOnServiceURL,
		Issuer: Issuer{
			XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Issuer"},
			Value:   s.config.ServiceProvider.EntityID,
		},
		NameIDPolicy: NameIDPolicy{
			Format:      idp.NameIDFormat,
			AllowCreate: true,
		},
		RequestedAuthnContext: RequestedAuthnContext{
			Comparison: "exact",
			AuthnContextClassRef: []string{
				"urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport",
			},
		},
		AssertionConsumerServiceURL: s.config.ServiceProvider.AssertionConsumerServiceURL,
		ProtocolBinding:             "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
	}

	// Marshal to XML
	xmlData, err := xml.MarshalIndent(authnRequest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AuthnRequest: %w", err)
	}

	requestXML := xml.Header + string(xmlData)

	// Sign the request if required
	if s.config.ServiceProvider.AuthnRequestsSigned {
		signedXML, err := s.signXML(requestXML)
		if err != nil {
			return nil, fmt.Errorf("failed to sign AuthnRequest: %w", err)
		}
		requestXML = signedXML
	}

	// Encode for HTTP-Redirect binding
	encodedRequest := base64.StdEncoding.EncodeToString([]byte(requestXML))

	// Build redirect URL
	params := url.Values{}
	params.Add("SAMLRequest", encodedRequest)
	if relayState != "" {
		params.Add("RelayState", relayState)
	}

	redirectURL := fmt.Sprintf("%s?%s", idp.SingleSignOnServiceURL, params.Encode())

	// Store request state
	samlState := &OAuthState{
		State:     requestID,
		Provider:  "saml:" + idpEntityID,
		ExpiresAt: time.Now().Add(10 * time.Minute),
		CreatedAt: time.Now(),
	}

	if err := s.stateStore.StoreState(ctx, samlState); err != nil {
		return nil, fmt.Errorf("failed to store SAML state: %w", err)
	}

	return &SAMLAuthRequest{
		ID:          requestID,
		URL:         redirectURL,
		RelayState:  relayState,
		RequestXML:  requestXML,
		IDPEntityID: idpEntityID,
		CreatedAt:   time.Now().Unix(),
	}, nil
}

// HandleResponse processes a SAML response
func (s *SAMLService) HandleResponse(ctx context.Context, samlResponse string, relayState string) (*SAMLResult, error) {
	// Decode the SAML response
	decodedResponse, err := base64.StdEncoding.DecodeString(samlResponse)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SAML response: %w", err)
	}

	// Parse the SAML response
	var response Response
	if err := xml.Unmarshal(decodedResponse, &response); err != nil {
		return nil, fmt.Errorf("failed to parse SAML response: %w", err)
	}

	// Validate the response
	if err := s.validateResponse(&response); err != nil {
		return nil, fmt.Errorf("SAML response validation failed: %w", err)
	}

	// Extract assertion
	if len(response.Assertion) == 0 {
		return nil, fmt.Errorf("no assertions found in SAML response")
	}

	assertion := response.Assertion[0]

	// Validate assertion
	if err := s.validateAssertion(&assertion); err != nil {
		return nil, fmt.Errorf("SAML assertion validation failed: %w", err)
	}

	// Extract user information
	result, err := s.extractUserInfo(&assertion, response.Issuer.Value)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user info: %w", err)
	}

	return result, nil
}

// ValidateAssertion validates a SAML assertion
func (s *SAMLService) ValidateAssertion(ctx context.Context, assertion *SAMLAssertion) error {
	// Check time bounds
	now := time.Now().Unix()

	if assertion.NotBefore > 0 && now < assertion.NotBefore-s.config.ClockSkewTolerance {
		return fmt.Errorf("assertion not yet valid")
	}

	if assertion.NotOnOrAfter > 0 && now > assertion.NotOnOrAfter+s.config.ClockSkewTolerance {
		return fmt.Errorf("assertion has expired")
	}

	// Check audience
	if assertion.Audience != s.config.ServiceProvider.EntityID {
		return fmt.Errorf("assertion audience mismatch")
	}

	// Check assertion age
	if s.config.MaxAssertionAge > 0 {
		assertionAge := now - assertion.NotBefore
		if assertionAge > s.config.MaxAssertionAge {
			return fmt.Errorf("assertion too old")
		}
	}

	return nil
}

// validateResponse validates the SAML response structure
func (s *SAMLService) validateResponse(response *Response) error {
	// Check response status
	if response.Status.StatusCode.Value != "urn:oasis:names:tc:SAML:2.0:status:Success" {
		return fmt.Errorf("SAML response status: %s", response.Status.StatusCode.Value)
	}

	// Check destination
	if response.Destination != s.config.ServiceProvider.AssertionConsumerServiceURL {
		return fmt.Errorf("response destination mismatch")
	}

	// Verify signature if required
	idp, exists := s.config.IdentityProviders[response.Issuer.Value]
	if exists && idp.WantResponseSigned {
		if err := s.verifySignature(response.Signature, idp.X509Certificate); err != nil {
			return fmt.Errorf("response signature verification failed: %w", err)
		}
	}

	return nil
}

// validateAssertion validates the SAML assertion
func (s *SAMLService) validateAssertion(assertion *Assertion) error {
	// Check time conditions
	now := time.Now()

	if assertion.Conditions.NotBefore != "" {
		notBefore, err := time.Parse("2006-01-02T15:04:05Z", assertion.Conditions.NotBefore)
		if err != nil {
			return fmt.Errorf("invalid NotBefore time: %w", err)
		}
		if now.Before(notBefore.Add(-time.Duration(s.config.ClockSkewTolerance) * time.Second)) {
			return fmt.Errorf("assertion not yet valid")
		}
	}

	if assertion.Conditions.NotOnOrAfter != "" {
		notOnOrAfter, err := time.Parse("2006-01-02T15:04:05Z", assertion.Conditions.NotOnOrAfter)
		if err != nil {
			return fmt.Errorf("invalid NotOnOrAfter time: %w", err)
		}
		if now.After(notOnOrAfter.Add(time.Duration(s.config.ClockSkewTolerance) * time.Second)) {
			return fmt.Errorf("assertion has expired")
		}
	}

	// Check audience restriction
	if len(assertion.Conditions.AudienceRestriction) > 0 {
		audienceFound := false
		for _, restriction := range assertion.Conditions.AudienceRestriction {
			for _, audience := range restriction.Audience {
				if audience == s.config.ServiceProvider.EntityID {
					audienceFound = true
					break
				}
			}
			if audienceFound {
				break
			}
		}
		if !audienceFound {
			return fmt.Errorf("assertion audience restriction failed")
		}
	}

	// Verify assertion signature if required
	if assertion.Signature != nil {
		idp, exists := s.config.IdentityProviders[assertion.Issuer.Value]
		if exists && idp.WantAssertionsSigned {
			if err := s.verifySignature(assertion.Signature, idp.X509Certificate); err != nil {
				return fmt.Errorf("assertion signature verification failed: %w", err)
			}
		}
	}

	return nil
}

// extractUserInfo extracts user information from SAML assertion
func (s *SAMLService) extractUserInfo(assertion *Assertion, idpEntityID string) (*SAMLResult, error) {
	result := &SAMLResult{
		NameID:      assertion.Subject.NameID.Value,
		IDPEntityID: idpEntityID,
		Attributes:  make(map[string]string),
		ExpiresAt:   time.Now().Add(time.Duration(s.config.SessionTimeout) * time.Second).Unix(),
	}

	// Extract session index
	if len(assertion.AuthnStatement) > 0 {
		result.SessionIndex = assertion.AuthnStatement[0].SessionIndex
	}

	// Extract attributes
	if assertion.AttributeStatement != nil {
		for _, attr := range assertion.AttributeStatement.Attribute {
			if len(attr.AttributeValue) > 0 {
				result.Attributes[attr.Name] = attr.AttributeValue[0]
			}
		}
	}

	// Map attributes to user fields
	mapping := s.config.AttributeMapping

	if email, exists := result.Attributes[mapping.Email]; exists {
		result.Email = email
	}

	// Try to get name from different attribute mappings
	if fullName, exists := result.Attributes[mapping.FullName]; exists {
		result.Name = fullName
	} else {
		firstName := result.Attributes[mapping.FirstName]
		lastName := result.Attributes[mapping.LastName]
		if firstName != "" || lastName != "" {
			result.Name = strings.TrimSpace(firstName + " " + lastName)
		}
	}

	// If no email found, this is an error
	if result.Email == "" {
		return nil, fmt.Errorf("no email attribute found in SAML assertion")
	}

	return result, nil
}

// signXML signs XML content (placeholder implementation)
func (s *SAMLService) signXML(xmlContent string) (string, error) {
	// This is a simplified implementation
	// In production, you would use a proper XML signing library
	// For now, we'll return the unsigned XML
	return xmlContent, nil
}

// verifySignature verifies XML signature (placeholder implementation)
func (s *SAMLService) verifySignature(signature *Signature, certificate string) error {
	// This is a simplified implementation
	// In production, you would use a proper XML signature verification library
	if signature == nil {
		return fmt.Errorf("no signature present")
	}

	// Parse certificate
	block, _ := pem.Decode([]byte(certificate))
	if block == nil {
		return fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Verify certificate is valid
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("certificate is not valid at current time")
	}

	// In a real implementation, you would verify the actual XML signature
	// For now, we'll just validate the certificate format
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return fmt.Errorf("certificate does not contain RSA public key")
	}

	return nil
}

// generateSecureID generates a cryptographically secure ID
func (s *SAMLService) generateSecureID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "_" + fmt.Sprintf("%x", b), nil
}
