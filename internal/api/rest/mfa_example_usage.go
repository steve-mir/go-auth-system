package rest

import (
	"fmt"
	"log"

	"github.com/steve-mir/go-auth-system/internal/service/mfa"
)

// ExampleMFAUsage demonstrates how to use the MFA REST API endpoints
func ExampleMFAUsage() {
	fmt.Println("=== MFA REST API Usage Examples ===")

	// Note: These examples show the request/response patterns
	// In a real application, you would make HTTP requests to these endpoints

	// Example 1: Setup TOTP MFA
	fmt.Println("\n1. Setting up TOTP MFA:")
	totpSetupRequest := &mfa.SetupTOTPRequest{
		UserID:      "123e4567-e89b-12d3-a456-426614174000",
		AccountName: "user@example.com",
		Issuer:      "MyApp",
	}
	fmt.Printf("POST /api/v1/mfa/totp/setup\n")
	fmt.Printf("Request: %+v\n", totpSetupRequest)
	fmt.Printf("Response: Contains QR code URL, secret, backup codes, and setup token\n")

	// Example 2: Verify TOTP code
	fmt.Println("\n2. Verifying TOTP code:")
	totpVerifyRequest := &mfa.VerifyTOTPRequest{
		UserID:   "123e4567-e89b-12d3-a456-426614174000",
		ConfigID: "456e7890-e89b-12d3-a456-426614174001",
		Code:     "123456",
		ForLogin: true,
	}
	fmt.Printf("POST /api/v1/mfa/totp/verify\n")
	fmt.Printf("Request: %+v\n", totpVerifyRequest)
	fmt.Printf("Response: Validation result and completion status\n")

	// Example 3: Setup SMS MFA
	fmt.Println("\n3. Setting up SMS MFA:")
	smsSetupRequest := &mfa.SetupSMSRequest{
		UserID:      "123e4567-e89b-12d3-a456-426614174000",
		PhoneNumber: "+1234567890",
	}
	fmt.Printf("POST /api/v1/mfa/sms/setup\n")
	fmt.Printf("Request: %+v\n", smsSetupRequest)
	fmt.Printf("Response: Contains masked phone number and backup codes\n")

	// Example 4: Send SMS code
	fmt.Println("\n4. Sending SMS verification code:")
	sendSMSRequest := &mfa.SendSMSCodeRequest{
		UserID:   "123e4567-e89b-12d3-a456-426614174000",
		ConfigID: "456e7890-e89b-12d3-a456-426614174002",
		ForLogin: true,
	}
	fmt.Printf("POST /api/v1/mfa/sms/send-code\n")
	fmt.Printf("Request: %+v\n", sendSMSRequest)
	fmt.Printf("Response: Confirmation of code sent and expiration time\n")

	// Example 5: Setup Email MFA
	fmt.Println("\n5. Setting up Email MFA:")
	emailSetupRequest := &mfa.SetupEmailRequest{
		UserID: "123e4567-e89b-12d3-a456-426614174000",
		Email:  "user@example.com",
	}
	fmt.Printf("POST /api/v1/mfa/email/setup\n")
	fmt.Printf("Request: %+v\n", emailSetupRequest)
	fmt.Printf("Response: Contains masked email and backup codes\n")

	// Example 6: Send Email code
	fmt.Println("\n6. Sending Email verification code:")
	sendEmailRequest := &mfa.SendEmailCodeRequest{
		UserID:   "123e4567-e89b-12d3-a456-426614174000",
		ConfigID: "456e7890-e89b-12d3-a456-426614174003",
		ForLogin: true,
	}
	fmt.Printf("POST /api/v1/mfa/email/send-code\n")
	fmt.Printf("Request: %+v\n", sendEmailRequest)
	fmt.Printf("Response: Confirmation of code sent and expiration time\n")

	// Example 7: Setup WebAuthn
	fmt.Println("\n7. Setting up WebAuthn:")
	webauthnSetupRequest := &mfa.SetupWebAuthnRequest{
		UserID:      "123e4567-e89b-12d3-a456-426614174000",
		DisplayName: "My Security Key",
	}
	fmt.Printf("POST /api/v1/mfa/webauthn/setup\n")
	fmt.Printf("Request: %+v\n", webauthnSetupRequest)
	fmt.Printf("Response: Contains credential creation options for WebAuthn\n")

	// Example 8: Generate backup codes
	fmt.Println("\n8. Generating backup codes:")
	backupCodesRequest := &mfa.GenerateBackupCodesRequest{
		UserID:   "123e4567-e89b-12d3-a456-426614174000",
		ConfigID: "456e7890-e89b-12d3-a456-426614174001",
	}
	fmt.Printf("POST /api/v1/mfa/backup-codes/generate\n")
	fmt.Printf("Request: %+v\n", backupCodesRequest)
	fmt.Printf("Response: Array of new backup codes\n")

	// Example 9: Get user MFA methods
	fmt.Println("\n9. Getting user MFA methods:")
	fmt.Printf("GET /api/v1/mfa/methods/123e4567-e89b-12d3-a456-426614174000\n")
	fmt.Printf("Response: List of all configured MFA methods for the user\n")

	// Example 10: Disable MFA method
	fmt.Println("\n10. Disabling MFA method:")
	disableMFARequest := &mfa.DisableMFARequest{
		UserID:   "123e4567-e89b-12d3-a456-426614174000",
		ConfigID: "456e7890-e89b-12d3-a456-426614174001",
		Method:   "totp",
	}
	fmt.Printf("POST /api/v1/mfa/disable\n")
	fmt.Printf("Request: %+v\n", disableMFARequest)
	fmt.Printf("Response: Confirmation message\n")

	// Example 11: Validate MFA for login
	fmt.Println("\n11. Validating MFA for login:")
	validateLoginRequest := &mfa.ValidateMFAForLoginRequest{
		UserID: "123e4567-e89b-12d3-a456-426614174000",
	}
	fmt.Printf("POST /api/v1/mfa/validate-login\n")
	fmt.Printf("Request: %+v\n", validateLoginRequest)
	fmt.Printf("Response: MFA requirements and available methods\n")
}

// ExampleMFAIntegrationWithEmailService demonstrates how MFA integrates with the email service
func ExampleMFAIntegrationWithEmailService() {
	fmt.Println("\n=== MFA Integration with Email Service ===")

	fmt.Println("\nThe MFA service integrates with the email service in the following ways:")

	fmt.Println("\n1. Email MFA Code Delivery:")
	fmt.Println("   - When a user requests an email MFA code via POST /api/v1/mfa/email/send-code")
	fmt.Println("   - The MFA service calls the email service's SendMFACodeEmail method")
	fmt.Println("   - The email service uses the configured email provider (SMTP, SendGrid, etc.)")
	fmt.Println("   - A 6-digit verification code is sent to the user's email")

	fmt.Println("\n2. Email Templates Used:")
	fmt.Println("   - MFA verification code email template")
	fmt.Println("   - Account security notification emails")
	fmt.Println("   - MFA setup confirmation emails")

	fmt.Println("\n3. Email Service Configuration:")
	fmt.Println("   - The email service must be properly configured with a provider")
	fmt.Println("   - Templates should be set up for MFA-related emails")
	fmt.Println("   - Rate limiting should be configured to prevent abuse")

	fmt.Println("\n4. Security Considerations:")
	fmt.Println("   - Email codes expire after 5 minutes (configurable)")
	fmt.Println("   - Codes are single-use only")
	fmt.Println("   - Failed attempts are logged for security monitoring")
	fmt.Println("   - Email addresses are masked in responses for privacy")
}

// ExampleMFAWorkflow demonstrates a complete MFA workflow
func ExampleMFAWorkflow() {
	fmt.Println("\n=== Complete MFA Workflow Example ===")

	fmt.Println("\n--- User Registration and MFA Setup ---")
	fmt.Println("1. User registers account via /api/v1/auth/register")
	fmt.Println("2. User logs in via /api/v1/auth/login")
	fmt.Println("3. User chooses to enable MFA")
	fmt.Println("4. User selects TOTP as preferred method")
	fmt.Println("5. POST /api/v1/mfa/totp/setup - Get QR code and setup token")
	fmt.Println("6. User scans QR code with authenticator app")
	fmt.Println("7. POST /api/v1/mfa/totp/verify - Verify setup with first code")
	fmt.Println("8. User saves backup codes securely")

	fmt.Println("\n--- Login with MFA ---")
	fmt.Println("1. User provides username/password via /api/v1/auth/login")
	fmt.Println("2. Auth service detects MFA is enabled for user")
	fmt.Println("3. POST /api/v1/mfa/validate-login - Check MFA requirements")
	fmt.Println("4. User is prompted to provide MFA verification")
	fmt.Println("5. User enters TOTP code from authenticator app")
	fmt.Println("6. POST /api/v1/mfa/totp/verify - Verify the code")
	fmt.Println("7. If valid, complete login process")

	fmt.Println("\n--- MFA Recovery with Backup Code ---")
	fmt.Println("1. User loses access to primary MFA method")
	fmt.Println("2. User chooses 'Use backup code' option")
	fmt.Println("3. POST /api/v1/mfa/backup-codes/verify - Verify backup code")
	fmt.Println("4. If valid, user gains access and should set up new MFA method")

	fmt.Println("\n--- Adding Additional MFA Methods ---")
	fmt.Println("1. User wants to add SMS as backup MFA method")
	fmt.Println("2. POST /api/v1/mfa/sms/setup - Setup SMS MFA")
	fmt.Println("3. POST /api/v1/mfa/sms/send-code - Send verification code")
	fmt.Println("4. POST /api/v1/mfa/sms/verify - Verify SMS code")
	fmt.Println("5. SMS MFA is now available as an option")

	fmt.Println("\n--- Managing MFA Methods ---")
	fmt.Println("1. GET /api/v1/mfa/methods/{userID} - View all MFA methods")
	fmt.Println("2. POST /api/v1/mfa/backup-codes/generate - Generate new backup codes")
	fmt.Println("3. POST /api/v1/mfa/disable - Disable specific MFA method")
}

// ExampleErrorHandling demonstrates error handling patterns
func ExampleErrorHandling() {
	fmt.Println("\n=== MFA Error Handling Examples ===")

	fmt.Println("\n1. Invalid TOTP Code:")
	fmt.Println("   Request: POST /api/v1/mfa/totp/verify with wrong code")
	fmt.Println("   Response: 401 Unauthorized")
	fmt.Println("   {\"error\": \"Invalid TOTP code\", \"message\": \"The provided code is incorrect or expired\"}")

	fmt.Println("\n2. Missing Required Fields:")
	fmt.Println("   Request: POST /api/v1/mfa/totp/setup without user_id")
	fmt.Println("   Response: 400 Bad Request")
	fmt.Println("   {\"error\": \"Invalid request body\", \"details\": \"user_id is required\"}")

	fmt.Println("\n3. MFA Method Not Found:")
	fmt.Println("   Request: POST /api/v1/mfa/totp/verify with non-existent config_id")
	fmt.Println("   Response: 404 Not Found")
	fmt.Println("   {\"error\": \"MFA configuration not found\"}")

	fmt.Println("\n4. Service Unavailable:")
	fmt.Println("   Request: Any MFA endpoint when email/SMS service is down")
	fmt.Println("   Response: 500 Internal Server Error")
	fmt.Println("   {\"error\": \"Failed to send verification code\", \"details\": \"email service unavailable\"}")

	fmt.Println("\n5. Rate Limiting:")
	fmt.Println("   Request: Too many verification attempts")
	fmt.Println("   Response: 429 Too Many Requests")
	fmt.Println("   {\"error\": \"Rate limit exceeded\", \"message\": \"Please wait before trying again\"}")
}

// ExampleSecurityBestPractices outlines security considerations
func ExampleSecurityBestPractices() {
	fmt.Println("\n=== MFA Security Best Practices ===")

	fmt.Println("\n1. Token Security:")
	fmt.Println("   - All MFA endpoints require valid JWT authentication")
	fmt.Println("   - Setup tokens are temporary and expire quickly")
	fmt.Println("   - Verification codes expire after 5 minutes")
	fmt.Println("   - Backup codes are single-use only")

	fmt.Println("\n2. Rate Limiting:")
	fmt.Println("   - Implement rate limiting on verification endpoints")
	fmt.Println("   - Limit SMS/email code sending frequency")
	fmt.Println("   - Block excessive failed verification attempts")

	fmt.Println("\n3. Audit Logging:")
	fmt.Println("   - Log all MFA setup and verification attempts")
	fmt.Println("   - Monitor for suspicious patterns")
	fmt.Println("   - Alert on multiple failed attempts")

	fmt.Println("\n4. Data Protection:")
	fmt.Println("   - TOTP secrets are encrypted at rest")
	fmt.Println("   - Backup codes are hashed before storage")
	fmt.Println("   - Phone numbers and emails are masked in responses")
	fmt.Println("   - Sensitive data is never logged")

	fmt.Println("\n5. WebAuthn Security:")
	fmt.Println("   - Use proper origin validation")
	fmt.Println("   - Implement user verification requirements")
	fmt.Println("   - Store credentials securely")
	fmt.Println("   - Validate attestation when required")
}

// RunMFAExamples runs all MFA examples
func RunMFAExamples() {
	log.Println("Running MFA REST API examples...")

	ExampleMFAUsage()
	ExampleMFAIntegrationWithEmailService()
	ExampleMFAWorkflow()
	ExampleErrorHandling()
	ExampleSecurityBestPractices()

	log.Println("MFA examples completed!")
}
