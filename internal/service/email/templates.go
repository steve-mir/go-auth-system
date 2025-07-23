package email

import (
	"context"
	"time"
)

// initializeDefaultTemplates creates the default email templates
func (s *Service) initializeDefaultTemplates(ctx context.Context) error {
	templates := s.getDefaultTemplates()

	for _, template := range templates {
		// Check if template already exists
		existing, err := s.templates.GetByID(ctx, template.ID)
		if err == nil && existing != nil {
			continue // Template already exists
		}

		if err := s.templates.Create(ctx, template); err != nil {
			s.logger.Warn("Failed to create default template", "template_id", template.ID, "error", err)
		}
	}

	return nil
}

// getDefaultTemplates returns the default email templates
func (s *Service) getDefaultTemplates() []*EmailTemplate {
	baseURL := s.config.Templates.BaseURL
	if baseURL == "" {
		baseURL = "https://your-app.com"
	}

	return []*EmailTemplate{
		{
			ID:          "welcome",
			Name:        "Welcome Email",
			Description: "Welcome new users to the platform",
			Subject:     "Welcome to {{app_name}}, {{name}}!",
			HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 28px;">Welcome to {{app_name}}!</h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px;">
        <h2 style="color: #333; margin-top: 0;">Hello {{name}},</h2>
        
        <p>We're excited to have you join our community! Your account has been successfully created and you're ready to get started.</p>
        
        <div style="background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #667eea;">
            <h3 style="margin-top: 0; color: #667eea;">What's next?</h3>
            <ul style="padding-left: 20px;">
                <li>Complete your profile setup</li>
                <li>Explore our features</li>
                <li>Connect with other users</li>
            </ul>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{base_url}}/dashboard" style="background: #667eea; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Get Started</a>
        </div>
        
        <p>If you have any questions, feel free to reach out to our support team.</p>
        
        <p>Best regards,<br>The {{app_name}} Team</p>
    </div>
</body>
</html>`,
			TextBody: `Welcome to {{app_name}}, {{name}}!

We're excited to have you join our community! Your account has been successfully created and you're ready to get started.

What's next?
- Complete your profile setup
- Explore our features  
- Connect with other users

Get started: {{base_url}}/dashboard

If you have any questions, feel free to reach out to our support team.

Best regards,
The {{app_name}} Team`,
			Variables: []string{"name", "app_name", "base_url"},
			Category:  "authentication",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		{
			ID:          "email-verification",
			Name:        "Email Verification",
			Description: "Email verification for new accounts",
			Subject:     "Verify your email address",
			HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Email</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #28a745;">
        <h1 style="color: #333; margin: 0; font-size: 28px;">Verify Your Email</h1>
    </div>
    
    <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
        <h2 style="color: #333; margin-top: 0;">Hello {{name}},</h2>
        
        <p>Thank you for signing up! To complete your registration, please verify your email address by clicking the button below.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{verification_url}}" style="background: #28a745; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; font-size: 16px;">Verify Email Address</a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace;">{{verification_url}}</p>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #856404;"><strong>Security Note:</strong> This verification link will expire in 24 hours for your security.</p>
        </div>
        
        <p>If you didn't create an account, you can safely ignore this email.</p>
        
        <p>Best regards,<br>The {{app_name}} Team</p>
    </div>
</body>
</html>`,
			TextBody: `Hello {{name}},

Thank you for signing up! To complete your registration, please verify your email address by visiting this link:

{{verification_url}}

This verification link will expire in 24 hours for your security.

If you didn't create an account, you can safely ignore this email.

Best regards,
The {{app_name}} Team`,
			Variables: []string{"name", "verification_url", "app_name"},
			Category:  "authentication",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		{
			ID:          "password-reset",
			Name:        "Password Reset",
			Description: "Password reset instructions",
			Subject:     "Reset your password",
			HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Reset</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #dc3545;">
        <h1 style="color: #333; margin: 0; font-size: 28px;">Password Reset</h1>
    </div>
    
    <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
        <h2 style="color: #333; margin-top: 0;">Hello {{name}},</h2>
        
        <p>We received a request to reset your password. If you made this request, click the button below to set a new password.</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{reset_url}}" style="background: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; font-size: 16px;">Reset Password</a>
        </div>
        
        <p>If the button doesn't work, you can copy and paste this link into your browser:</p>
        <p style="word-break: break-all; background: #f8f9fa; padding: 10px; border-radius: 4px; font-family: monospace;">{{reset_url}}</p>
        
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #721c24;"><strong>Security Note:</strong> This reset link will expire in 1 hour for your security. If you didn't request this reset, please ignore this email.</p>
        </div>
        
        <p>For your security, this password reset link can only be used once.</p>
        
        <p>Best regards,<br>The {{app_name}} Team</p>
    </div>
</body>
</html>`,
			TextBody: `Hello {{name}},

We received a request to reset your password. If you made this request, visit this link to set a new password:

{{reset_url}}

This reset link will expire in 1 hour for your security. If you didn't request this reset, please ignore this email.

For your security, this password reset link can only be used once.

Best regards,
The {{app_name}} Team`,
			Variables: []string{"name", "reset_url", "app_name"},
			Category:  "authentication",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		{
			ID:          "login-notification",
			Name:        "Login Notification",
			Description: "Notify users of new login activity",
			Subject:     "New login to your account",
			HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Notification</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #17a2b8;">
        <h1 style="color: #333; margin: 0; font-size: 28px;">Login Notification</h1>
    </div>
    
    <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
        <h2 style="color: #333; margin-top: 0;">Hello {{name}},</h2>
        
        <p>We detected a new login to your account. Here are the details:</p>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <table style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 8px 0; font-weight: bold; width: 30%;">Time:</td>
                    <td style="padding: 8px 0;">{{time}}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; font-weight: bold;">Location:</td>
                    <td style="padding: 8px 0;">{{location}}</td>
                </tr>
                <tr>
                    <td style="padding: 8px 0; font-weight: bold;">Device:</td>
                    <td style="padding: 8px 0;">{{device}}</td>
                </tr>
            </table>
        </div>
        
        <div style="background: #d1ecf1; border: 1px solid #bee5eb; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #0c5460;"><strong>Was this you?</strong> If you recognize this activity, no action is needed.</p>
        </div>
        
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #721c24;"><strong>Didn't recognize this login?</strong> Please secure your account immediately by changing your password and reviewing your account settings.</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{base_url}}/account/security" style="background: #17a2b8; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Review Account Security</a>
        </div>
        
        <p>Best regards,<br>The {{app_name}} Team</p>
    </div>
</body>
</html>`,
			TextBody: `Hello {{name}},

We detected a new login to your account. Here are the details:

Time: {{time}}
Location: {{location}}
Device: {{device}}

Was this you? If you recognize this activity, no action is needed.

Didn't recognize this login? Please secure your account immediately by changing your password and reviewing your account settings.

Review your account security: {{base_url}}/account/security

Best regards,
The {{app_name}} Team`,
			Variables: []string{"name", "time", "location", "device", "base_url", "app_name"},
			Category:  "security",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		{
			ID:          "mfa-code",
			Name:        "MFA Verification Code",
			Description: "Multi-factor authentication code",
			Subject:     "Your verification code",
			HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verification Code</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #6f42c1;">
        <h1 style="color: #333; margin: 0; font-size: 28px;">Verification Code</h1>
    </div>
    
    <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
        <h2 style="color: #333; margin-top: 0;">Hello {{name}},</h2>
        
        <p>Here's your verification code to complete your login:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <div style="background: #6f42c1; color: white; padding: 20px; border-radius: 10px; display: inline-block;">
                <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px; font-family: monospace;">{{code}}</div>
            </div>
        </div>
        
        <div style="background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #856404;"><strong>Important:</strong> This code will expire in 10 minutes for your security.</p>
        </div>
        
        <p>Enter this code in your login screen to complete the authentication process.</p>
        
        <p>If you didn't request this code, please ignore this email and consider changing your password.</p>
        
        <p>Best regards,<br>The {{app_name}} Team</p>
    </div>
</body>
</html>`,
			TextBody: `Hello {{name}},

Here's your verification code to complete your login:

{{code}}

This code will expire in 10 minutes for your security.

Enter this code in your login screen to complete the authentication process.

If you didn't request this code, please ignore this email and consider changing your password.

Best regards,
The {{app_name}} Team`,
			Variables: []string{"name", "code", "app_name"},
			Category:  "security",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		{
			ID:          "account-locked",
			Name:        "Account Locked",
			Description: "Notify user when account is locked",
			Subject:     "Your account has been locked",
			HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Locked</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #dc3545;">
        <h1 style="color: #333; margin: 0; font-size: 28px;">Account Locked</h1>
    </div>
    
    <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
        <h2 style="color: #333; margin-top: 0;">Hello {{name}},</h2>
        
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #721c24; font-weight: bold;">Your account has been temporarily locked due to multiple failed login attempts.</p>
        </div>
        
        <p>This is a security measure to protect your account from unauthorized access.</p>
        
        <h3 style="color: #dc3545;">What happened?</h3>
        <p>We detected several unsuccessful login attempts to your account, which triggered our security system to temporarily lock your account.</p>
        
        <h3 style="color: #dc3545;">What can you do?</h3>
        <ul>
            <li>Wait 30 minutes and try logging in again</li>
            <li>Reset your password if you've forgotten it</li>
            <li>Contact our support team if you need immediate assistance</li>
        </ul>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{base_url}}/reset-password" style="background: #dc3545; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold; margin-right: 10px;">Reset Password</a>
            <a href="{{base_url}}/support" style="background: #6c757d; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Contact Support</a>
        </div>
        
        <p>If you believe this was triggered in error, please contact our support team.</p>
        
        <p>Best regards,<br>The {{app_name}} Team</p>
    </div>
</body>
</html>`,
			TextBody: `Hello {{name}},

Your account has been temporarily locked due to multiple failed login attempts.

This is a security measure to protect your account from unauthorized access.

What happened?
We detected several unsuccessful login attempts to your account, which triggered our security system to temporarily lock your account.

What can you do?
- Wait 30 minutes and try logging in again
- Reset your password if you've forgotten it
- Contact our support team if you need immediate assistance

Reset your password: {{base_url}}/reset-password
Contact support: {{base_url}}/support

If you believe this was triggered in error, please contact our support team.

Best regards,
The {{app_name}} Team`,
			Variables: []string{"name", "base_url", "app_name"},
			Category:  "security",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},

		{
			ID:          "password-changed",
			Name:        "Password Changed",
			Description: "Confirm password change",
			Subject:     "Your password has been changed",
			HTMLBody: `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Password Changed</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: #f8f9fa; padding: 30px; text-align: center; border-radius: 10px 10px 0 0; border-bottom: 3px solid #28a745;">
        <h1 style="color: #333; margin: 0; font-size: 28px;">Password Changed</h1>
    </div>
    
    <div style="background: white; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e9ecef;">
        <h2 style="color: #333; margin-top: 0;">Hello {{name}},</h2>
        
        <div style="background: #d4edda; border: 1px solid #c3e6cb; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #155724; font-weight: bold;">✓ Your password has been successfully changed.</p>
        </div>
        
        <p>This email confirms that your account password was recently updated.</p>
        
        <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3 style="margin-top: 0; color: #333;">Security Tips:</h3>
            <ul style="margin-bottom: 0;">
                <li>Use a unique password for your account</li>
                <li>Enable two-factor authentication for extra security</li>
                <li>Never share your password with anyone</li>
                <li>Consider using a password manager</li>
            </ul>
        </div>
        
        <div style="background: #f8d7da; border: 1px solid #f5c6cb; padding: 15px; border-radius: 5px; margin: 20px 0;">
            <p style="margin: 0; color: #721c24;"><strong>Didn't change your password?</strong> If you didn't make this change, please contact our support team immediately.</p>
        </div>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{{base_url}}/account/security" style="background: #28a745; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; font-weight: bold;">Review Account Security</a>
        </div>
        
        <p>Best regards,<br>The {{app_name}} Team</p>
    </div>
</body>
</html>`,
			TextBody: `Hello {{name}},

Your password has been successfully changed.

This email confirms that your account password was recently updated.

Security Tips:
- Use a unique password for your account
- Enable two-factor authentication for extra security
- Never share your password with anyone
- Consider using a password manager

Didn't change your password? If you didn't make this change, please contact our support team immediately.

Review your account security: {{base_url}}/account/security

Best regards,
The {{app_name}} Team`,
			Variables: []string{"name", "base_url", "app_name"},
			Category:  "security",
			IsActive:  true,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
}
