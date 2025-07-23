package mfa

import (
	"time"

	"github.com/google/uuid"
)

// MFA method constants
const (
	MethodTOTP     = "totp"
	MethodSMS      = "sms"
	MethodEmail    = "email"
	MethodWebAuthn = "webauthn"
)

// TOTP Setup and Verification

// SetupTOTPRequest represents a TOTP setup request
type SetupTOTPRequest struct {
	UserID      string `json:"user_id" validate:"required,uuid"`
	AccountName string `json:"account_name,omitempty"` // Usually email or username
	Issuer      string `json:"issuer,omitempty"`       // Application name
}

// SetupTOTPResponse represents a TOTP setup response
type SetupTOTPResponse struct {
	ConfigID    uuid.UUID `json:"config_id"`
	Secret      string    `json:"secret"`
	QRCodeURL   string    `json:"qr_code_url"`
	BackupCodes []string  `json:"backup_codes"`
	SetupToken  string    `json:"setup_token"` // Temporary token for verification
	Message     string    `json:"message"`
}

// VerifyTOTPRequest represents a TOTP verification request
type VerifyTOTPRequest struct {
	UserID     string `json:"user_id,omitempty" validate:"omitempty,uuid"`
	ConfigID   string `json:"config_id,omitempty" validate:"omitempty,uuid"`
	SetupToken string `json:"setup_token,omitempty"` // For initial setup verification
	Code       string `json:"code" validate:"required,len=6"`
	ForLogin   bool   `json:"for_login,omitempty"` // True if this is for login verification
}

// VerifyTOTPResponse represents a TOTP verification response
type VerifyTOTPResponse struct {
	Valid         bool   `json:"valid"`
	ConfigID      string `json:"config_id,omitempty"`
	Message       string `json:"message"`
	SetupComplete bool   `json:"setup_complete,omitempty"` // True if setup was completed
}

// SMS Setup and Verification

// SetupSMSRequest represents an SMS MFA setup request
type SetupSMSRequest struct {
	UserID      string `json:"user_id" validate:"required,uuid"`
	PhoneNumber string `json:"phone_number" validate:"required,e164"`
}

// SetupSMSResponse represents an SMS MFA setup response
type SetupSMSResponse struct {
	ConfigID    uuid.UUID `json:"config_id"`
	PhoneNumber string    `json:"phone_number"` // Masked phone number
	BackupCodes []string  `json:"backup_codes"`
	Message     string    `json:"message"`
}

// SendSMSCodeRequest represents a request to send SMS verification code
type SendSMSCodeRequest struct {
	UserID   string `json:"user_id" validate:"required,uuid"`
	ConfigID string `json:"config_id,omitempty" validate:"omitempty,uuid"`
	ForLogin bool   `json:"for_login,omitempty"` // True if this is for login verification
}

// SendSMSCodeResponse represents a response to SMS code sending
type SendSMSCodeResponse struct {
	CodeSent    bool   `json:"code_sent"`
	ExpiresIn   int64  `json:"expires_in"` // Seconds until code expires
	Message     string `json:"message"`
	PhoneNumber string `json:"phone_number"` // Masked phone number
}

// VerifySMSRequest represents an SMS verification request
type VerifySMSRequest struct {
	UserID   string `json:"user_id,omitempty" validate:"omitempty,uuid"`
	ConfigID string `json:"config_id,omitempty" validate:"omitempty,uuid"`
	Code     string `json:"code" validate:"required,len=6"`
	ForLogin bool   `json:"for_login,omitempty"` // True if this is for login verification
}

// VerifySMSResponse represents an SMS verification response
type VerifySMSResponse struct {
	Valid    bool   `json:"valid"`
	ConfigID string `json:"config_id,omitempty"`
	Message  string `json:"message"`
}

// Email Setup and Verification

// SetupEmailRequest represents an email MFA setup request
type SetupEmailRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
	Email  string `json:"email" validate:"required,email"`
}

// SetupEmailResponse represents an email MFA setup response
type SetupEmailResponse struct {
	ConfigID    uuid.UUID `json:"config_id"`
	Email       string    `json:"email"` // Masked email
	BackupCodes []string  `json:"backup_codes"`
	Message     string    `json:"message"`
}

// SendEmailCodeRequest represents a request to send email verification code
type SendEmailCodeRequest struct {
	UserID   string `json:"user_id" validate:"required,uuid"`
	ConfigID string `json:"config_id,omitempty" validate:"omitempty,uuid"`
	ForLogin bool   `json:"for_login,omitempty"` // True if this is for login verification
}

// SendEmailCodeResponse represents a response to email code sending
type SendEmailCodeResponse struct {
	CodeSent  bool   `json:"code_sent"`
	ExpiresIn int64  `json:"expires_in"` // Seconds until code expires
	Message   string `json:"message"`
	Email     string `json:"email"` // Masked email
}

// VerifyEmailRequest represents an email verification request
type VerifyEmailRequest struct {
	UserID   string `json:"user_id,omitempty" validate:"omitempty,uuid"`
	ConfigID string `json:"config_id,omitempty" validate:"omitempty,uuid"`
	Code     string `json:"code" validate:"required,len=6"`
	ForLogin bool   `json:"for_login,omitempty"` // True if this is for login verification
}

// VerifyEmailResponse represents an email verification response
type VerifyEmailResponse struct {
	Valid    bool   `json:"valid"`
	ConfigID string `json:"config_id,omitempty"`
	Message  string `json:"message"`
}

// General MFA Operations

// GetUserMFAMethodsResponse represents user's MFA methods
type GetUserMFAMethodsResponse struct {
	Methods []MFAMethodInfo `json:"methods"`
}

// MFAMethodInfo represents information about an MFA method
type MFAMethodInfo struct {
	ID          uuid.UUID  `json:"id"`
	Method      string     `json:"method"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	DisplayName string     `json:"display_name"` // e.g., "SMS to +1***-***-1234"
}

// WebAuthn Setup and Verification

// SetupWebAuthnRequest represents a WebAuthn setup request
type SetupWebAuthnRequest struct {
	UserID      string `json:"user_id" validate:"required,uuid"`
	DisplayName string `json:"display_name,omitempty"` // Human-readable name for the credential
}

// SetupWebAuthnResponse represents a WebAuthn setup response
type SetupWebAuthnResponse struct {
	ConfigID           uuid.UUID          `json:"config_id"`
	CredentialCreation CredentialCreation `json:"credential_creation"`
	BackupCodes        []string           `json:"backup_codes"`
	Message            string             `json:"message"`
}

// FinishWebAuthnSetupRequest represents a request to finish WebAuthn setup
type FinishWebAuthnSetupRequest struct {
	UserID             string                     `json:"user_id" validate:"required,uuid"`
	ConfigID           string                     `json:"config_id" validate:"required,uuid"`
	CredentialResponse CredentialCreationResponse `json:"credential_response"`
}

// FinishWebAuthnSetupResponse represents a response to finish WebAuthn setup
type FinishWebAuthnSetupResponse struct {
	Success      bool   `json:"success"`
	ConfigID     string `json:"config_id"`
	Message      string `json:"message"`
	CredentialID string `json:"credential_id"`
}

// BeginWebAuthnLoginRequest represents a request to begin WebAuthn login
type BeginWebAuthnLoginRequest struct {
	UserID   string `json:"user_id,omitempty" validate:"omitempty,uuid"`
	ConfigID string `json:"config_id,omitempty" validate:"omitempty,uuid"`
	ForLogin bool   `json:"for_login,omitempty"` // True if this is for login verification
}

// BeginWebAuthnLoginResponse represents a response to begin WebAuthn login
type BeginWebAuthnLoginResponse struct {
	CredentialAssertion CredentialAssertion `json:"credential_assertion"`
	Message             string              `json:"message"`
}

// FinishWebAuthnLoginRequest represents a request to finish WebAuthn login
type FinishWebAuthnLoginRequest struct {
	UserID             string                      `json:"user_id,omitempty" validate:"omitempty,uuid"`
	ConfigID           string                      `json:"config_id,omitempty" validate:"omitempty,uuid"`
	CredentialResponse CredentialAssertionResponse `json:"credential_response"`
	ForLogin           bool                        `json:"for_login,omitempty"` // True if this is for login verification
}

// FinishWebAuthnLoginResponse represents a response to finish WebAuthn login
type FinishWebAuthnLoginResponse struct {
	Valid    bool   `json:"valid"`
	ConfigID string `json:"config_id,omitempty"`
	Message  string `json:"message"`
}

// WebAuthn credential structures (simplified versions of WebAuthn spec)
type CredentialCreation struct {
	PublicKey PublicKeyCredentialCreationOptions `json:"publicKey"`
}

type PublicKeyCredentialCreationOptions struct {
	Challenge              []byte                          `json:"challenge"`
	RP                     RelyingParty                    `json:"rp"`
	User                   UserEntity                      `json:"user"`
	PubKeyCredParams       []PublicKeyCredentialParameters `json:"pubKeyCredParams"`
	AuthenticatorSelection AuthenticatorSelectionCriteria  `json:"authenticatorSelection,omitempty"`
	Timeout                int                             `json:"timeout,omitempty"`
	ExcludeCredentials     []PublicKeyCredentialDescriptor `json:"excludeCredentials,omitempty"`
}

type CredentialAssertion struct {
	PublicKey PublicKeyCredentialRequestOptions `json:"publicKey"`
}

type PublicKeyCredentialRequestOptions struct {
	Challenge        []byte                          `json:"challenge"`
	Timeout          int                             `json:"timeout,omitempty"`
	RPID             string                          `json:"rpId,omitempty"`
	AllowCredentials []PublicKeyCredentialDescriptor `json:"allowCredentials,omitempty"`
	UserVerification string                          `json:"userVerification,omitempty"`
}

type RelyingParty struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type UserEntity struct {
	ID          []byte `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

type PublicKeyCredentialParameters struct {
	Type string `json:"type"`
	Alg  int    `json:"alg"`
}

type AuthenticatorSelectionCriteria struct {
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
}

type PublicKeyCredentialDescriptor struct {
	Type       string   `json:"type"`
	ID         []byte   `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

type CredentialCreationResponse struct {
	ID       string                           `json:"id"`
	RawID    []byte                           `json:"rawId"`
	Type     string                           `json:"type"`
	Response AuthenticatorAttestationResponse `json:"response"`
}

type CredentialAssertionResponse struct {
	ID       string                         `json:"id"`
	RawID    []byte                         `json:"rawId"`
	Type     string                         `json:"type"`
	Response AuthenticatorAssertionResponse `json:"response"`
}

type AuthenticatorAttestationResponse struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AttestationObject []byte `json:"attestationObject"`
}

type AuthenticatorAssertionResponse struct {
	ClientDataJSON    []byte `json:"clientDataJSON"`
	AuthenticatorData []byte `json:"authenticatorData"`
	Signature         []byte `json:"signature"`
	UserHandle        []byte `json:"userHandle,omitempty"`
}

// WebAuthn credential storage structure
type WebAuthnCredential struct {
	ID              []byte            `json:"id"`
	PublicKey       []byte            `json:"public_key"`
	AttestationType string            `json:"attestation_type"`
	Authenticator   AuthenticatorData `json:"authenticator"`
	DisplayName     string            `json:"display_name"`
}

type AuthenticatorData struct {
	AAGUID       []byte `json:"aaguid"`
	SignCount    uint32 `json:"sign_count"`
	CloneWarning bool   `json:"clone_warning"`
}

// DisableMFARequest represents a request to disable MFA
type DisableMFARequest struct {
	UserID   string `json:"user_id" validate:"required,uuid"`
	ConfigID string `json:"config_id" validate:"required,uuid"`
	Method   string `json:"method" validate:"required,oneof=totp sms email webauthn"`
}

// Backup Codes

// GenerateBackupCodesRequest represents a request to generate backup codes
type GenerateBackupCodesRequest struct {
	UserID   string `json:"user_id" validate:"required,uuid"`
	ConfigID string `json:"config_id" validate:"required,uuid"`
}

// GenerateBackupCodesResponse represents backup codes generation response
type GenerateBackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
	Message     string   `json:"message"`
}

// VerifyBackupCodeRequest represents a backup code verification request
type VerifyBackupCodeRequest struct {
	UserID     string `json:"user_id" validate:"required,uuid"`
	BackupCode string `json:"backup_code" validate:"required"`
	ForLogin   bool   `json:"for_login,omitempty"` // True if this is for login verification
}

// VerifyBackupCodeResponse represents a backup code verification response
type VerifyBackupCodeResponse struct {
	Valid   bool   `json:"valid"`
	Message string `json:"message"`
}

// Login Validation

// ValidateMFAForLoginRequest represents MFA validation during login
type ValidateMFAForLoginRequest struct {
	UserID string `json:"user_id" validate:"required,uuid"`
}

// ValidateMFAForLoginResponse represents MFA validation response for login
type ValidateMFAForLoginResponse struct {
	MFARequired bool            `json:"mfa_required"`
	Methods     []string        `json:"methods,omitempty"`   // Available MFA methods
	Configs     []MFAConfigInfo `json:"configs,omitempty"`   // MFA config info for client
	Challenge   string          `json:"challenge,omitempty"` // Challenge token for MFA flow
}

// MFAConfigInfo represents MFA configuration info for client
type MFAConfigInfo struct {
	ID          string `json:"id"`
	Method      string `json:"method"`
	DisplayName string `json:"display_name"`
}

// Internal structures for verification codes
type VerificationCode struct {
	Code      string    `json:"code"`
	UserID    string    `json:"user_id"`
	ConfigID  string    `json:"config_id,omitempty"`
	Method    string    `json:"method"`
	ExpiresAt time.Time `json:"expires_at"`
	ForLogin  bool      `json:"for_login"`
}

// TOTP setup token for temporary verification during setup
type TOTPSetupToken struct {
	UserID    string    `json:"user_id"`
	ConfigID  string    `json:"config_id"`
	Secret    string    `json:"secret"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Constants for code generation and validation
const (
	// Code lengths
	TOTPCodeLength   = 6
	SMSCodeLength    = 6
	EmailCodeLength  = 6
	BackupCodeLength = 8

	// Expiration times (in seconds)
	TOTPSetupTokenExpiration = 300 // 5 minutes
	SMSCodeExpiration        = 300 // 5 minutes
	EmailCodeExpiration      = 600 // 10 minutes
	TOTPWindowSize           = 1   // Allow 1 time step before/after current

	// Backup codes
	BackupCodesCount = 10

	// Cache key prefixes
	CacheKeyTOTPSetup     = "mfa:totp:setup:"
	CacheKeySMSCode       = "mfa:sms:code:"
	CacheKeyEmailCode     = "mfa:email:code:"
	CacheKeyWebAuthnSetup = "mfa:webauthn:setup:"
	CacheKeyWebAuthnLogin = "mfa:webauthn:login:"

	// WebAuthn constants
	WebAuthnTimeout         = 60000 // 60 seconds in milliseconds
	WebAuthnChallengeLength = 32    // 32 bytes for challenge
)
