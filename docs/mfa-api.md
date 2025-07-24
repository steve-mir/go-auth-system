# MFA API Documentation

This document describes the Multi-Factor Authentication (MFA) REST API endpoints available in the go-auth-system.

## Base URL

All MFA endpoints are available under `/api/v1/mfa` and require authentication.

## Authentication

All MFA endpoints require a valid JWT token in the Authorization header:
```
Authorization: Bearer <your-jwt-token>
```

## TOTP (Time-based One-Time Password) Endpoints

### Setup TOTP
**POST** `/api/v1/mfa/totp/setup`

Sets up TOTP-based MFA for a user.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "account_name": "user@example.com",
  "issuer": "MyApp"
}
```

**Response:**
```json
{
  "config_id": "456e7890-e89b-12d3-a456-426614174001",
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code_url": "otpauth://totp/MyApp:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=MyApp",
  "backup_codes": ["12345678", "87654321", "..."],
  "setup_token": "temp-setup-token-123",
  "message": "TOTP setup initiated. Scan QR code and verify with a code."
}
```

### Verify TOTP
**POST** `/api/v1/mfa/totp/verify`

Verifies a TOTP code for authentication.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174001",
  "code": "123456",
  "for_login": true
}
```

**Response:**
```json
{
  "valid": true,
  "config_id": "456e7890-e89b-12d3-a456-426614174001",
  "message": "TOTP code verified successfully",
  "setup_complete": true
}
```

## SMS MFA Endpoints

### Setup SMS MFA
**POST** `/api/v1/mfa/sms/setup`

Sets up SMS-based MFA for a user.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "phone_number": "+1234567890"
}
```

**Response:**
```json
{
  "config_id": "456e7890-e89b-12d3-a456-426614174002",
  "phone_number": "+1***-***-7890",
  "backup_codes": ["12345678", "87654321", "..."],
  "message": "SMS MFA setup completed"
}
```

### Send SMS Code
**POST** `/api/v1/mfa/sms/send-code`

Sends an SMS verification code.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174002",
  "for_login": true
}
```

**Response:**
```json
{
  "code_sent": true,
  "expires_in": 300,
  "message": "SMS code sent successfully",
  "phone_number": "+1***-***-7890"
}
```

### Verify SMS Code
**POST** `/api/v1/mfa/sms/verify`

Verifies an SMS code for authentication.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174002",
  "code": "123456",
  "for_login": true
}
```

**Response:**
```json
{
  "valid": true,
  "config_id": "456e7890-e89b-12d3-a456-426614174002",
  "message": "SMS code verified successfully"
}
```

## Email MFA Endpoints

### Setup Email MFA
**POST** `/api/v1/mfa/email/setup`

Sets up email-based MFA for a user.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com"
}
```

**Response:**
```json
{
  "config_id": "456e7890-e89b-12d3-a456-426614174003",
  "email": "u***@example.com",
  "backup_codes": ["12345678", "87654321", "..."],
  "message": "Email MFA setup completed"
}
```

### Send Email Code
**POST** `/api/v1/mfa/email/send-code`

Sends an email verification code.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174003",
  "for_login": true
}
```

**Response:**
```json
{
  "code_sent": true,
  "expires_in": 300,
  "message": "Email code sent successfully",
  "email": "u***@example.com"
}
```

### Verify Email Code
**POST** `/api/v1/mfa/email/verify`

Verifies an email code for authentication.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174003",
  "code": "123456",
  "for_login": true
}
```

**Response:**
```json
{
  "valid": true,
  "config_id": "456e7890-e89b-12d3-a456-426614174003",
  "message": "Email code verified successfully"
}
```

## WebAuthn Endpoints

### Setup WebAuthn
**POST** `/api/v1/mfa/webauthn/setup`

Initiates WebAuthn credential registration.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "display_name": "My Security Key"
}
```

**Response:**
```json
{
  "config_id": "456e7890-e89b-12d3-a456-426614174004",
  "credential_creation": {
    "publicKey": {
      "challenge": "base64-encoded-challenge",
      "rp": {
        "id": "example.com",
        "name": "MyApp"
      },
      "user": {
        "id": "base64-user-id",
        "name": "user@example.com",
        "displayName": "User Name"
      },
      "pubKeyCredParams": [
        {"type": "public-key", "alg": -7}
      ]
    }
  },
  "backup_codes": ["12345678", "87654321", "..."],
  "message": "WebAuthn setup initiated"
}
```

### Finish WebAuthn Setup
**POST** `/api/v1/mfa/webauthn/setup/finish`

Completes WebAuthn credential registration.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174004",
  "credential_response": {
    "id": "credential-id",
    "rawId": "base64-raw-id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64-client-data",
      "attestationObject": "base64-attestation-object"
    }
  }
}
```

**Response:**
```json
{
  "success": true,
  "config_id": "456e7890-e89b-12d3-a456-426614174004",
  "message": "WebAuthn setup completed successfully",
  "credential_id": "credential-id-123"
}
```

### Begin WebAuthn Login
**POST** `/api/v1/mfa/webauthn/login/begin`

Initiates WebAuthn authentication.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174004",
  "for_login": true
}
```

**Response:**
```json
{
  "credential_assertion": {
    "publicKey": {
      "challenge": "base64-encoded-challenge",
      "allowCredentials": [
        {
          "type": "public-key",
          "id": "base64-credential-id"
        }
      ]
    }
  },
  "message": "WebAuthn login challenge generated"
}
```

### Finish WebAuthn Login
**POST** `/api/v1/mfa/webauthn/login/finish`

Completes WebAuthn authentication.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174004",
  "credential_response": {
    "id": "credential-id",
    "rawId": "base64-raw-id",
    "type": "public-key",
    "response": {
      "clientDataJSON": "base64-client-data",
      "authenticatorData": "base64-authenticator-data",
      "signature": "base64-signature"
    }
  },
  "for_login": true
}
```

**Response:**
```json
{
  "valid": true,
  "config_id": "456e7890-e89b-12d3-a456-426614174004",
  "message": "WebAuthn authentication successful"
}
```

## Backup Codes Endpoints

### Generate Backup Codes
**POST** `/api/v1/mfa/backup-codes/generate`

Generates new backup codes for MFA recovery.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174001"
}
```

**Response:**
```json
{
  "backup_codes": [
    "12345678",
    "87654321",
    "11223344",
    "55667788",
    "99887766"
  ],
  "message": "New backup codes generated successfully"
}
```

### Verify Backup Code
**POST** `/api/v1/mfa/backup-codes/verify`

Verifies a backup code for MFA recovery.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "backup_code": "12345678",
  "for_login": true
}
```

**Response:**
```json
{
  "valid": true,
  "message": "Backup code verified successfully"
}
```

## General MFA Endpoints

### Get User MFA Methods
**GET** `/api/v1/mfa/methods/{userID}`

Retrieves all MFA methods configured for a user.

**Response:**
```json
{
  "methods": [
    {
      "id": "456e7890-e89b-12d3-a456-426614174001",
      "method": "totp",
      "enabled": true,
      "created_at": "2024-01-15T10:30:00Z",
      "last_used_at": "2024-01-20T14:45:00Z",
      "display_name": "Authenticator App"
    },
    {
      "id": "456e7890-e89b-12d3-a456-426614174002",
      "method": "sms",
      "enabled": true,
      "created_at": "2024-01-16T11:00:00Z",
      "last_used_at": null,
      "display_name": "SMS to +1***-***-7890"
    }
  ]
}
```

### Disable MFA Method
**POST** `/api/v1/mfa/disable`

Disables a specific MFA method for a user.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "config_id": "456e7890-e89b-12d3-a456-426614174001",
  "method": "totp"
}
```

**Response:**
```json
{
  "message": "MFA method disabled successfully"
}
```

### Validate MFA for Login
**POST** `/api/v1/mfa/validate-login`

Validates MFA requirements during the login process.

**Request Body:**
```json
{
  "user_id": "123e4567-e89b-12d3-a456-426614174000"
}
```

**Response:**
```json
{
  "mfa_required": true,
  "methods": ["totp", "sms", "email"],
  "configs": [
    {
      "id": "456e7890-e89b-12d3-a456-426614174001",
      "method": "totp",
      "display_name": "Authenticator App"
    },
    {
      "id": "456e7890-e89b-12d3-a456-426614174002",
      "method": "sms",
      "display_name": "SMS to +1***-***-7890"
    }
  ],
  "challenge": "mfa-challenge-token-123"
}
```

## Error Responses

All endpoints may return the following error responses:

### 400 Bad Request
```json
{
  "error": "Invalid request body",
  "details": "validation error details"
}
```

### 401 Unauthorized
```json
{
  "error": "Invalid TOTP code",
  "message": "The provided code is incorrect or expired"
}
```

### 500 Internal Server Error
```json
{
  "error": "Failed to setup TOTP",
  "details": "internal error details"
}
```

## MFA Flow Examples

### Complete TOTP Setup Flow

1. **Setup TOTP**
   ```bash
   curl -X POST /api/v1/mfa/totp/setup \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"user_id": "user-123", "account_name": "user@example.com", "issuer": "MyApp"}'
   ```

2. **User scans QR code and enters verification code**

3. **Verify TOTP to complete setup**
   ```bash
   curl -X POST /api/v1/mfa/totp/verify \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"user_id": "user-123", "setup_token": "temp-token", "code": "123456"}'
   ```

### Login with MFA Flow

1. **User provides username/password (handled by auth service)**

2. **Check if MFA is required**
   ```bash
   curl -X POST /api/v1/mfa/validate-login \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"user_id": "user-123"}'
   ```

3. **If MFA required, user chooses method and provides verification**
   ```bash
   curl -X POST /api/v1/mfa/totp/verify \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"user_id": "user-123", "config_id": "config-456", "code": "123456", "for_login": true}'
   ```

4. **Complete login process (handled by auth service)**

## Security Considerations

- All MFA endpoints require authentication
- Backup codes should be stored securely and shown only once
- TOTP secrets should never be logged or exposed
- WebAuthn challenges should be time-limited
- Rate limiting should be applied to verification endpoints
- Failed verification attempts should be logged for security monitoring