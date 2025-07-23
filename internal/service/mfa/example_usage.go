package mfa

import (
	"context"
	"fmt"
	"log"

	"github.com/google/uuid"
	"github.com/steve-mir/go-auth-system/internal/config"
)

// ExampleMFAUsage demonstrates how to use the MFA service
func ExampleMFAUsage() {
	// This is an example of how to use the MFA service
	// In a real application, you would inject actual implementations

	ctx := context.Background()

	// Example configuration
	cfg := &config.Config{
		Features: config.FeaturesConfig{
			MFA: config.MFAConfig{
				Enabled: true,
				TOTP: config.TOTPConfig{
					Enabled: true,
					Issuer:  "My App",
					Period:  30,
					Digits:  6,
				},
				SMS: config.SMSConfig{
					Enabled:  true,
					Provider: "twilio",
				},
				Email: config.EmailConfig{
					Enabled: true,
					Subject: "Your verification code",
				},
				WebAuthn: config.WebAuthnConfig{
					Enabled:       true,
					RPDisplayName: "My App",
					RPID:          "localhost",
					RPName:        "My App",
					RPOrigin:      []string{"http://localhost:8080"},
				},
			},
		},
	}

	// Example dependencies (you would use real implementations)
	deps := &Dependencies{
		MFARepo:      nil, // Implement MFARepository
		UserRepo:     nil, // Implement UserRepository
		SMSService:   nil, // Implement SMSService
		EmailService: nil, // Implement EmailService
		CacheService: nil, // Implement CacheService
		Encryptor:    nil, // Implement Encryptor
	}

	// Create MFA service
	mfaService := NewMFAService(cfg, deps)

	userID := uuid.New().String()

	// Example 1: Setup TOTP MFA
	fmt.Println("=== TOTP MFA Setup ===")
	totpReq := &SetupTOTPRequest{
		UserID:      userID,
		AccountName: "user@example.com",
		Issuer:      "My App",
	}

	totpResp, err := mfaService.SetupTOTP(ctx, totpReq)
	if err != nil {
		log.Printf("TOTP setup failed: %v", err)
	} else {
		fmt.Printf("TOTP Secret: %s\n", totpResp.Secret)
		fmt.Printf("QR Code URL: %s\n", totpResp.QRCodeURL)
		fmt.Printf("Setup Token: %s\n", totpResp.SetupToken)
		fmt.Printf("Backup Codes: %v\n", totpResp.BackupCodes)
	}

	// Example 2: Verify TOTP during setup
	fmt.Println("\n=== TOTP Verification (Setup) ===")
	verifyReq := &VerifyTOTPRequest{
		SetupToken: totpResp.SetupToken,
		Code:       "123456", // User enters code from authenticator app
	}

	verifyResp, err := mfaService.VerifyTOTP(ctx, verifyReq)
	if err != nil {
		log.Printf("TOTP verification failed: %v", err)
	} else {
		fmt.Printf("Verification successful: %t\n", verifyResp.Valid)
		fmt.Printf("Setup complete: %t\n", verifyResp.SetupComplete)
	}

	// Example 3: Setup SMS MFA
	fmt.Println("\n=== SMS MFA Setup ===")
	smsReq := &SetupSMSRequest{
		UserID:      userID,
		PhoneNumber: "+1234567890",
	}

	smsResp, err := mfaService.SetupSMS(ctx, smsReq)
	if err != nil {
		log.Printf("SMS setup failed: %v", err)
	} else {
		fmt.Printf("SMS setup complete for: %s\n", smsResp.PhoneNumber)
		fmt.Printf("Backup Codes: %v\n", smsResp.BackupCodes)
	}

	// Example 4: Send SMS verification code
	fmt.Println("\n=== Send SMS Code ===")
	sendSMSReq := &SendSMSCodeRequest{
		UserID:   userID,
		ForLogin: true,
	}

	sendSMSResp, err := mfaService.SendSMSCode(ctx, sendSMSReq)
	if err != nil {
		log.Printf("SMS code sending failed: %v", err)
	} else {
		fmt.Printf("SMS code sent to: %s\n", sendSMSResp.PhoneNumber)
		fmt.Printf("Code expires in: %d seconds\n", sendSMSResp.ExpiresIn)
	}

	// Example 5: Verify SMS code
	fmt.Println("\n=== Verify SMS Code ===")
	verifySMSReq := &VerifySMSRequest{
		UserID:   userID,
		Code:     "123456", // User enters code from SMS
		ForLogin: true,
	}

	verifySMSResp, err := mfaService.VerifySMS(ctx, verifySMSReq)
	if err != nil {
		log.Printf("SMS verification failed: %v", err)
	} else {
		fmt.Printf("SMS verification successful: %t\n", verifySMSResp.Valid)
	}

	// Example 6: Setup Email MFA
	fmt.Println("\n=== Email MFA Setup ===")
	emailReq := &SetupEmailRequest{
		UserID: userID,
		Email:  "user@example.com",
	}

	emailResp, err := mfaService.SetupEmail(ctx, emailReq)
	if err != nil {
		log.Printf("Email setup failed: %v", err)
	} else {
		fmt.Printf("Email setup complete for: %s\n", emailResp.Email)
		fmt.Printf("Backup Codes: %v\n", emailResp.BackupCodes)
	}

	// Example 7: Get user's MFA methods
	fmt.Println("\n=== Get User MFA Methods ===")
	methodsResp, err := mfaService.GetUserMFAMethods(ctx, userID)
	if err != nil {
		log.Printf("Failed to get MFA methods: %v", err)
	} else {
		fmt.Printf("User has %d MFA methods:\n", len(methodsResp.Methods))
		for _, method := range methodsResp.Methods {
			fmt.Printf("- %s (%s) - Enabled: %t\n", method.DisplayName, method.Method, method.Enabled)
		}
	}

	// Example 8: Validate MFA for login
	fmt.Println("\n=== Validate MFA for Login ===")
	loginReq := &ValidateMFAForLoginRequest{
		UserID: userID,
	}

	loginResp, err := mfaService.ValidateMFAForLogin(ctx, loginReq)
	if err != nil {
		log.Printf("MFA validation failed: %v", err)
	} else {
		fmt.Printf("MFA Required: %t\n", loginResp.MFARequired)
		if loginResp.MFARequired {
			fmt.Printf("Available methods: %v\n", loginResp.Methods)
			fmt.Printf("Challenge token: %s\n", loginResp.Challenge)
		}
	}

	// Example 9: Generate new backup codes
	fmt.Println("\n=== Generate Backup Codes ===")
	if len(methodsResp.Methods) > 0 {
		backupReq := &GenerateBackupCodesRequest{
			UserID:   userID,
			ConfigID: methodsResp.Methods[0].ID.String(),
		}

		backupResp, err := mfaService.GenerateBackupCodes(ctx, backupReq)
		if err != nil {
			log.Printf("Backup code generation failed: %v", err)
		} else {
			fmt.Printf("New backup codes generated: %v\n", backupResp.BackupCodes)
		}
	}

	// Example 10: Verify backup code
	fmt.Println("\n=== Verify Backup Code ===")
	backupVerifyReq := &VerifyBackupCodeRequest{
		UserID:     userID,
		BackupCode: "12345678", // User enters backup code
		ForLogin:   true,
	}

	backupVerifyResp, err := mfaService.VerifyBackupCode(ctx, backupVerifyReq)
	if err != nil {
		log.Printf("Backup code verification failed: %v", err)
	} else {
		fmt.Printf("Backup code verification: %t\n", backupVerifyResp.Valid)
	}

	// Example 11: Setup WebAuthn MFA
	fmt.Println("\n=== WebAuthn MFA Setup ===")
	webAuthnReq := &SetupWebAuthnRequest{
		UserID:      userID,
		DisplayName: "User's Security Key",
	}

	webAuthnResp, err := mfaService.SetupWebAuthn(ctx, webAuthnReq)
	if err != nil {
		log.Printf("WebAuthn setup failed: %v", err)
	} else {
		fmt.Printf("WebAuthn setup initiated\n")
		fmt.Printf("Config ID: %s\n", webAuthnResp.ConfigID.String())
		fmt.Printf("Challenge: %x\n", webAuthnResp.CredentialCreation.PublicKey.Challenge)
		fmt.Printf("RP ID: %s\n", webAuthnResp.CredentialCreation.PublicKey.RP.ID)
		fmt.Printf("RP Name: %s\n", webAuthnResp.CredentialCreation.PublicKey.RP.Name)
		fmt.Printf("User Name: %s\n", webAuthnResp.CredentialCreation.PublicKey.User.Name)
		fmt.Printf("Backup Codes: %v\n", webAuthnResp.BackupCodes)
		fmt.Printf("Message: %s\n", webAuthnResp.Message)
	}

	// Example 12: Finish WebAuthn Setup (would be called after user completes credential creation)
	fmt.Println("\n=== Finish WebAuthn Setup ===")
	if webAuthnResp != nil {
		// In a real application, this would contain the actual credential response from the browser
		finishWebAuthnReq := &FinishWebAuthnSetupRequest{
			UserID:   userID,
			ConfigID: webAuthnResp.ConfigID.String(),
			CredentialResponse: CredentialCreationResponse{
				ID:    "example-credential-id",
				RawID: []byte("example-raw-id"),
				Type:  "public-key",
				Response: AuthenticatorAttestationResponse{
					ClientDataJSON:    []byte(`{"type":"webauthn.create","challenge":"dGVzdA","origin":"http://localhost:8080"}`),
					AttestationObject: []byte("example-attestation-object"),
				},
			},
		}

		finishWebAuthnResp, err := mfaService.FinishWebAuthnSetup(ctx, finishWebAuthnReq)
		if err != nil {
			log.Printf("WebAuthn setup completion failed: %v", err)
		} else {
			fmt.Printf("WebAuthn setup completed successfully\n")
			fmt.Printf("Success: %t\n", finishWebAuthnResp.Success)
			fmt.Printf("Config ID: %s\n", finishWebAuthnResp.ConfigID)
			fmt.Printf("Credential ID: %s\n", finishWebAuthnResp.CredentialID)
			fmt.Printf("Message: %s\n", finishWebAuthnResp.Message)
		}
	}

	// Example 13: Begin WebAuthn Login
	fmt.Println("\n=== Begin WebAuthn Login ===")
	beginWebAuthnReq := &BeginWebAuthnLoginRequest{
		UserID:   userID,
		ForLogin: true,
	}

	beginWebAuthnResp, err := mfaService.BeginWebAuthnLogin(ctx, beginWebAuthnReq)
	if err != nil {
		log.Printf("WebAuthn login initiation failed: %v", err)
	} else {
		fmt.Printf("WebAuthn login challenge generated\n")
		fmt.Printf("Challenge: %x\n", beginWebAuthnResp.CredentialAssertion.PublicKey.Challenge)
		fmt.Printf("RP ID: %s\n", beginWebAuthnResp.CredentialAssertion.PublicKey.RPID)
		fmt.Printf("Timeout: %d\n", beginWebAuthnResp.CredentialAssertion.PublicKey.Timeout)
		fmt.Printf("Message: %s\n", beginWebAuthnResp.Message)
	}

	// Example 14: Finish WebAuthn Login (would be called after user completes authentication)
	fmt.Println("\n=== Finish WebAuthn Login ===")
	if beginWebAuthnResp != nil {
		// In a real application, this would contain the actual assertion response from the browser
		finishWebAuthnLoginReq := &FinishWebAuthnLoginRequest{
			UserID:   userID,
			ForLogin: true,
			CredentialResponse: CredentialAssertionResponse{
				ID:    "example-credential-id",
				RawID: []byte("example-raw-id"),
				Type:  "public-key",
				Response: AuthenticatorAssertionResponse{
					ClientDataJSON:    []byte(`{"type":"webauthn.get","challenge":"dGVzdA","origin":"http://localhost:8080"}`),
					AuthenticatorData: []byte("example-authenticator-data"),
					Signature:         []byte("example-signature"),
				},
			},
		}

		finishWebAuthnLoginResp, err := mfaService.FinishWebAuthnLogin(ctx, finishWebAuthnLoginReq)
		if err != nil {
			log.Printf("WebAuthn login completion failed: %v", err)
		} else {
			fmt.Printf("WebAuthn login completed\n")
			fmt.Printf("Valid: %t\n", finishWebAuthnLoginResp.Valid)
			fmt.Printf("Config ID: %s\n", finishWebAuthnLoginResp.ConfigID)
			fmt.Printf("Message: %s\n", finishWebAuthnLoginResp.Message)
		}
	}

	// Example 15: Disable MFA method
	fmt.Println("\n=== Disable MFA Method ===")
	if len(methodsResp.Methods) > 0 {
		disableReq := &DisableMFARequest{
			UserID:   userID,
			ConfigID: methodsResp.Methods[0].ID.String(),
			Method:   methodsResp.Methods[0].Method,
		}

		err := mfaService.DisableMFA(ctx, disableReq)
		if err != nil {
			log.Printf("MFA disable failed: %v", err)
		} else {
			fmt.Printf("MFA method disabled successfully\n")
		}
	}

	fmt.Println("\n=== MFA Service Example Complete ===")
}

// MFAWorkflow demonstrates a complete MFA workflow
func MFAWorkflow() {
	fmt.Println("=== Complete MFA Workflow ===")

	// 1. User Registration/Login
	fmt.Println("1. User logs in successfully with username/password")

	// 2. Check if MFA is required
	fmt.Println("2. System checks if MFA is required for user")

	// 3. If MFA required, present options
	fmt.Println("3. If MFA required:")
	fmt.Println("   - Show available MFA methods (TOTP, SMS, Email, WebAuthn)")
	fmt.Println("   - User selects preferred method")

	// 4. Send verification challenge
	fmt.Println("4. System sends verification challenge:")
	fmt.Println("   - TOTP: User enters code from authenticator app")
	fmt.Println("   - SMS: System sends code via SMS")
	fmt.Println("   - Email: System sends code via email")
	fmt.Println("   - WebAuthn: User uses hardware key or biometric authentication")

	// 5. Verify response
	fmt.Println("5. User enters verification code")
	fmt.Println("6. System verifies code and completes authentication")

	// 6. Backup codes
	fmt.Println("7. If verification fails, user can use backup codes")

	// 7. MFA Setup (for new users)
	fmt.Println("\n=== MFA Setup Workflow ===")
	fmt.Println("1. User goes to security settings")
	fmt.Println("2. User chooses to enable MFA")
	fmt.Println("3. User selects MFA method:")
	fmt.Println("   - TOTP: Scan QR code with authenticator app")
	fmt.Println("   - SMS: Enter and verify phone number")
	fmt.Println("   - Email: Enter and verify email address")
	fmt.Println("4. System generates and shows backup codes")
	fmt.Println("5. User saves backup codes securely")
	fmt.Println("6. MFA is now enabled for the user")
}

// SecurityBestPractices outlines MFA security considerations
func SecurityBestPractices() {
	fmt.Println("=== MFA Security Best Practices ===")

	fmt.Println("1. Code Generation:")
	fmt.Println("   - Use cryptographically secure random number generation")
	fmt.Println("   - Codes should be time-limited (5-10 minutes)")
	fmt.Println("   - Use constant-time comparison for code verification")

	fmt.Println("2. Storage Security:")
	fmt.Println("   - Encrypt all sensitive data (phone numbers, emails, secrets)")
	fmt.Println("   - Use secure key management")
	fmt.Println("   - Store backup codes with one-time use enforcement")

	fmt.Println("3. Rate Limiting:")
	fmt.Println("   - Limit verification attempts per user/IP")
	fmt.Println("   - Implement progressive delays for failed attempts")
	fmt.Println("   - Limit code generation requests")

	fmt.Println("4. TOTP Considerations:")
	fmt.Println("   - Allow time window for clock skew (±30 seconds)")
	fmt.Println("   - Use strong secret generation (160+ bits)")
	fmt.Println("   - Provide clear setup instructions")

	fmt.Println("5. SMS/Email Security:")
	fmt.Println("   - Use reputable service providers")
	fmt.Println("   - Implement delivery confirmation")
	fmt.Println("   - Consider SIM swapping risks for SMS")

	fmt.Println("6. Backup Codes:")
	fmt.Println("   - Generate sufficient codes (8-10)")
	fmt.Println("   - Enforce single-use policy")
	fmt.Println("   - Allow regeneration when needed")

	fmt.Println("7. WebAuthn/FIDO2 Security:")
	fmt.Println("   - Use proper challenge generation (32+ bytes)")
	fmt.Println("   - Validate origin and RP ID strictly")
	fmt.Println("   - Implement proper attestation verification")
	fmt.Println("   - Handle signature counter for clone detection")
	fmt.Println("   - Support multiple authenticator types")

	fmt.Println("8. User Experience:")
	fmt.Println("   - Provide clear error messages")
	fmt.Println("   - Support multiple MFA methods")
	fmt.Println("   - Allow graceful fallback options")
	fmt.Println("   - Test across different browsers and devices")
}
