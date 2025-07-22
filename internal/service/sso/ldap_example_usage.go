package sso

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/steve-mir/go-auth-system/internal/config"
)

// ExampleLDAPUsage demonstrates how to use the LDAP integration
func ExampleLDAPUsage() {
	// Example LDAP configuration
	ldapConfig := &LDAPConfig{
		Host:         "ldap.company.com",
		Port:         389,
		BaseDN:       "DC=company,DC=com",
		BindDN:       "CN=service-account,CN=Users,DC=company,DC=com",
		BindPassword: "service-password",
		UserFilter:   "(&(objectClass=user)(sAMAccountName={username}))",
		GroupFilter:  "(objectClass=group)",
		TLS:          false,
		Attributes: LDAPAttributeMapping{
			Username:    "sAMAccountName",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "displayName",
			Groups:      "memberOf",
			Enabled:     "userAccountControl",
		},
		GroupSync: LDAPGroupSyncConfig{
			Enabled:       true,
			SyncInterval:  3600, // 1 hour
			GroupBaseDN:   "CN=Users,DC=company,DC=com",
			GroupFilter:   "(objectClass=group)",
			MemberAttr:    "member",
			GroupNameAttr: "cn",
			AutoCreate:    false,
			RolePrefix:    "AD_",
		},
		Connection: LDAPConnectionConfig{
			Timeout:        30,
			ReadTimeout:    30,
			WriteTimeout:   30,
			MaxConnections: 10,
			IdleTimeout:    300,
			SkipTLSVerify:  false,
			StartTLS:       false,
		},
	}

	// Create LDAP client
	client, err := NewLDAPClient(ldapConfig)
	if err != nil {
		log.Fatalf("Failed to create LDAP client: %v", err)
	}
	defer client.Close()

	ctx := context.Background()

	// Example 1: Search for a user
	fmt.Println("=== Example 1: Search User ===")
	user, err := client.SearchUser(ctx, "john.doe")
	if err != nil {
		log.Printf("User search failed: %v", err)
	} else if user != nil {
		fmt.Printf("Found user: %s (%s)\n", user.DisplayName, user.Email)
		fmt.Printf("DN: %s\n", user.DN)
		fmt.Printf("Enabled: %t\n", user.Enabled)
		fmt.Printf("Groups: %v\n", user.Groups)
	} else {
		fmt.Println("User not found")
	}

	// Example 2: Authenticate a user
	fmt.Println("\n=== Example 2: Authenticate User ===")
	result, err := client.Authenticate(ctx, "john.doe", "user-password")
	if err != nil {
		log.Printf("Authentication failed: %v", err)
	} else {
		fmt.Printf("Authentication successful for: %s\n", result.Username)
		fmt.Printf("Email: %s\n", result.Email)
		fmt.Printf("Groups: %v\n", result.Groups)
		fmt.Printf("Is new user: %t\n", result.IsNewUser)
	}

	// Example 3: Get user groups
	fmt.Println("\n=== Example 3: Get User Groups ===")
	if user != nil {
		groups, err := client.GetUserGroups(ctx, user.DN)
		if err != nil {
			log.Printf("Failed to get user groups: %v", err)
		} else {
			fmt.Printf("User groups: %v\n", groups)
		}
	}

	// Example 4: Sync user information
	fmt.Println("\n=== Example 4: Sync User ===")
	syncResult, err := client.SyncUser(ctx, "john.doe")
	if err != nil {
		log.Printf("User sync failed: %v", err)
	} else {
		fmt.Printf("Sync successful for: %s\n", syncResult.Username)
		fmt.Printf("Updated: %t\n", syncResult.Updated)
		fmt.Printf("Changes: %v\n", syncResult.Changes)
		fmt.Printf("Sync time: %s\n", time.Unix(syncResult.SyncTime, 0))
	}
}

// ExampleSSO_LDAPIntegration demonstrates LDAP integration with SSO service
func ExampleSSO_LDAPIntegration() {
	// Example application configuration with LDAP enabled
	cfg := &config.Config{
		Features: config.FeaturesConfig{
			EnterpriseSSO: config.EnterpriseSSO{
				LDAP: config.LDAPConfig{
					Enabled:      true,
					Host:         "ldap.company.com",
					Port:         389,
					BaseDN:       "DC=company,DC=com",
					BindDN:       "CN=service-account,CN=Users,DC=company,DC=com",
					BindPassword: "service-password",
					UserFilter:   "(&(objectClass=user)(sAMAccountName={username}))",
					GroupFilter:  "(objectClass=group)",
					TLS:          false,
				},
			},
		},
		Security: config.SecurityConfig{
			PasswordHash: config.PasswordHashConfig{
				Algorithm: "argon2",
			},
		},
	}

	// Create SSO service with LDAP support
	// Note: In real usage, you would inject proper dependencies
	ssoService := &ssoService{
		config: cfg,
		// userRepo, socialAccountRepo, stateStore, hashService, encryptor would be injected
	}

	// Build LDAP config and initialize client
	ldapConfig := ssoService.buildLDAPConfig(cfg)
	ldapClient, err := NewLDAPClient(ldapConfig)
	if err != nil {
		log.Fatalf("Failed to initialize LDAP client: %v", err)
	}
	ssoService.ldapClient = ldapClient

	ctx := context.Background()

	// Example 1: LDAP Authentication through SSO service
	fmt.Println("=== Example 1: SSO LDAP Authentication ===")
	ldapResult, err := ssoService.AuthenticateLDAP(ctx, "john.doe", "user-password")
	if err != nil {
		log.Printf("LDAP authentication failed: %v", err)
	} else {
		fmt.Printf("LDAP authentication successful\n")
		fmt.Printf("User ID: %s\n", ldapResult.UserID)
		fmt.Printf("Username: %s\n", ldapResult.Username)
		fmt.Printf("Email: %s\n", ldapResult.Email)
		fmt.Printf("Is new user: %t\n", ldapResult.IsNewUser)
		fmt.Printf("Groups: %v\n", ldapResult.Groups)
	}

	// Example 2: Search LDAP user through SSO service
	fmt.Println("\n=== Example 2: SSO LDAP User Search ===")
	ldapUser, err := ssoService.SearchLDAPUser(ctx, "jane.smith")
	if err != nil {
		log.Printf("LDAP user search failed: %v", err)
	} else if ldapUser != nil {
		fmt.Printf("Found LDAP user: %s\n", ldapUser.DisplayName)
		fmt.Printf("Email: %s\n", ldapUser.Email)
		fmt.Printf("DN: %s\n", ldapUser.DN)
		fmt.Printf("Enabled: %t\n", ldapUser.Enabled)
	}

	// Example 3: Get LDAP user groups through SSO service
	fmt.Println("\n=== Example 3: SSO LDAP User Groups ===")
	groups, err := ssoService.GetLDAPUserGroups(ctx, "john.doe")
	if err != nil {
		log.Printf("Failed to get LDAP user groups: %v", err)
	} else {
		fmt.Printf("LDAP user groups: %v\n", groups)
	}

	// Example 4: Sync LDAP user through SSO service
	fmt.Println("\n=== Example 4: SSO LDAP User Sync ===")
	syncResult, err := ssoService.SyncLDAPUser(ctx, "john.doe")
	if err != nil {
		log.Printf("LDAP user sync failed: %v", err)
	} else {
		fmt.Printf("LDAP user sync successful\n")
		fmt.Printf("User ID: %s\n", syncResult.UserID)
		fmt.Printf("Username: %s\n", syncResult.Username)
		fmt.Printf("Updated: %t\n", syncResult.Updated)
		fmt.Printf("Changes: %v\n", syncResult.Changes)
	}
}

// ExampleLDAPConfiguration shows different LDAP configuration examples
func ExampleLDAPConfiguration() {
	fmt.Println("=== LDAP Configuration Examples ===")

	// Example 1: Active Directory configuration
	fmt.Println("\n--- Active Directory Configuration ---")
	adConfig := &LDAPConfig{
		Host:         "ad.company.com",
		Port:         389,
		BaseDN:       "DC=company,DC=com",
		BindDN:       "CN=ldap-service,CN=Users,DC=company,DC=com",
		BindPassword: "service-password",
		UserFilter:   "(&(objectClass=user)(sAMAccountName={username}))",
		GroupFilter:  "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))",
		TLS:          false,
		Attributes: LDAPAttributeMapping{
			Username:    "sAMAccountName",
			Email:       "userPrincipalName",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "displayName",
			Groups:      "memberOf",
			Enabled:     "userAccountControl",
		},
		GroupSync: LDAPGroupSyncConfig{
			Enabled:       true,
			GroupBaseDN:   "CN=Users,DC=company,DC=com",
			GroupFilter:   "(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))",
			MemberAttr:    "member",
			GroupNameAttr: "cn",
		},
	}
	fmt.Printf("AD Config - Host: %s, BaseDN: %s\n", adConfig.Host, adConfig.BaseDN)

	// Example 2: OpenLDAP configuration
	fmt.Println("\n--- OpenLDAP Configuration ---")
	openLDAPConfig := &LDAPConfig{
		Host:         "ldap.company.com",
		Port:         389,
		BaseDN:       "ou=people,dc=company,dc=com",
		BindDN:       "cn=admin,dc=company,dc=com",
		BindPassword: "admin-password",
		UserFilter:   "(&(objectClass=inetOrgPerson)(uid={username}))",
		GroupFilter:  "(objectClass=groupOfNames)",
		TLS:          false,
		Attributes: LDAPAttributeMapping{
			Username:    "uid",
			Email:       "mail",
			FirstName:   "givenName",
			LastName:    "sn",
			DisplayName: "cn",
			Groups:      "memberOf",
			Enabled:     "", // OpenLDAP doesn't have a standard enabled attribute
		},
		GroupSync: LDAPGroupSyncConfig{
			Enabled:       true,
			GroupBaseDN:   "ou=groups,dc=company,dc=com",
			GroupFilter:   "(objectClass=groupOfNames)",
			MemberAttr:    "member",
			GroupNameAttr: "cn",
		},
	}
	fmt.Printf("OpenLDAP Config - Host: %s, BaseDN: %s\n", openLDAPConfig.Host, openLDAPConfig.BaseDN)

	// Example 3: LDAPS (LDAP over TLS) configuration
	fmt.Println("\n--- LDAPS Configuration ---")
	ldapsConfig := &LDAPConfig{
		Host:         "ldaps.company.com",
		Port:         636,
		BaseDN:       "DC=company,DC=com",
		BindDN:       "CN=service,CN=Users,DC=company,DC=com",
		BindPassword: "service-password",
		UserFilter:   "(&(objectClass=user)(sAMAccountName={username}))",
		TLS:          true,
		Connection: LDAPConnectionConfig{
			SkipTLSVerify: false, // Verify TLS certificates in production
			StartTLS:      false, // Use LDAPS, not StartTLS
		},
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
	fmt.Printf("LDAPS Config - Host: %s, Port: %d, TLS: %t\n", ldapsConfig.Host, ldapsConfig.Port, ldapsConfig.TLS)

	// Example 4: StartTLS configuration
	fmt.Println("\n--- StartTLS Configuration ---")
	startTLSConfig := &LDAPConfig{
		Host:         "ldap.company.com",
		Port:         389,
		BaseDN:       "DC=company,DC=com",
		BindDN:       "CN=service,CN=Users,DC=company,DC=com",
		BindPassword: "service-password",
		UserFilter:   "(&(objectClass=user)(sAMAccountName={username}))",
		TLS:          false,
		Connection: LDAPConnectionConfig{
			StartTLS:      true, // Use StartTLS to upgrade connection
			SkipTLSVerify: false,
		},
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
	fmt.Printf("StartTLS Config - Host: %s, StartTLS: %t\n", startTLSConfig.Host, startTLSConfig.Connection.StartTLS)
}

// ExampleLDAPErrorHandling demonstrates error handling patterns
func ExampleLDAPErrorHandling() {
	fmt.Println("=== LDAP Error Handling Examples ===")

	// Example configuration
	config := &LDAPConfig{
		Host:         "ldap.company.com",
		Port:         389,
		BaseDN:       "DC=company,DC=com",
		BindDN:       "CN=service,CN=Users,DC=company,DC=com",
		BindPassword: "service-password",
		Attributes: LDAPAttributeMapping{
			Username: "sAMAccountName",
			Email:    "mail",
		},
	}

	client, err := NewLDAPClient(config)
	if err != nil {
		// Handle connection errors
		fmt.Printf("Connection error: %v\n", err)
		return
	}
	defer client.Close()

	ctx := context.Background()

	// Example 1: Handle user not found
	fmt.Println("\n--- Handle User Not Found ---")
	user, err := client.SearchUser(ctx, "nonexistent-user")
	if err != nil {
		fmt.Printf("Search error: %v\n", err)
	} else if user == nil {
		fmt.Println("User not found (this is normal)")
	} else {
		fmt.Printf("User found: %s\n", user.Username)
	}

	// Example 2: Handle authentication failure
	fmt.Println("\n--- Handle Authentication Failure ---")
	_, err = client.Authenticate(ctx, "testuser", "wrong-password")
	if err != nil {
		// Check error type
		if ldapErr, ok := err.(*LDAPAuthenticationFailedError); ok {
			fmt.Printf("Authentication failed: %v\n", ldapErr)
		} else {
			fmt.Printf("Other error: %v\n", err)
		}
	}

	// Example 3: Handle disabled user
	fmt.Println("\n--- Handle Disabled User ---")
	// This would typically happen during authentication
	// if the user account is disabled in Active Directory

	// Example 4: Handle connection timeout
	fmt.Println("\n--- Handle Connection Timeout ---")
	timeoutConfig := &LDAPConfig{
		Host:   "unreachable-host.company.com",
		Port:   389,
		BaseDN: "DC=company,DC=com",
		Connection: LDAPConnectionConfig{
			Timeout: 5, // Short timeout for quick failure
		},
	}

	_, err = NewLDAPClient(timeoutConfig)
	if err != nil {
		fmt.Printf("Connection timeout error: %v\n", err)
	}
}

// ExampleLDAPBestPractices demonstrates best practices for LDAP integration
func ExampleLDAPBestPractices() {
	fmt.Println("=== LDAP Best Practices ===")

	// Best Practice 1: Use service account with minimal permissions
	fmt.Println("\n--- Service Account Configuration ---")
	fmt.Println("✓ Create dedicated service account for LDAP binding")
	fmt.Println("✓ Grant only necessary permissions (read user/group info)")
	fmt.Println("✓ Use strong password and rotate regularly")
	fmt.Println("✓ Monitor service account usage")

	// Best Practice 2: Secure connection configuration
	fmt.Println("\n--- Secure Connection Configuration ---")
	secureConfig := &LDAPConfig{
		Host: "ldaps.company.com",
		Port: 636,
		TLS:  true,
		Connection: LDAPConnectionConfig{
			SkipTLSVerify: false, // Always verify certificates in production
			Timeout:       30,    // Reasonable timeout
		},
	}
	fmt.Printf("✓ Use LDAPS (port %d) or StartTLS for encryption\n", secureConfig.Port)
	fmt.Printf("✓ Verify TLS certificates: %t\n", !secureConfig.Connection.SkipTLSVerify)

	// Best Practice 3: Efficient search filters
	fmt.Println("\n--- Efficient Search Filters ---")
	fmt.Println("✓ Use specific filters to limit search scope")
	fmt.Println("✓ Index commonly searched attributes")
	fmt.Println("✓ Avoid wildcard searches when possible")

	efficientFilters := []string{
		"(&(objectClass=user)(sAMAccountName={username}))",                       // Specific user search
		"(&(objectClass=group)(groupType:1.2.840.113556.1.4.803:=2147483648))",   // Security groups only
		"(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))", // Enabled users only
	}

	for i, filter := range efficientFilters {
		fmt.Printf("✓ Filter %d: %s\n", i+1, filter)
	}

	// Best Practice 4: Connection pooling and caching
	fmt.Println("\n--- Connection Management ---")
	poolConfig := &LDAPConnectionConfig{
		MaxConnections: 10,  // Limit concurrent connections
		IdleTimeout:    300, // Close idle connections
		Timeout:        30,  // Connection timeout
	}
	fmt.Printf("✓ Max connections: %d\n", poolConfig.MaxConnections)
	fmt.Printf("✓ Idle timeout: %d seconds\n", poolConfig.IdleTimeout)
	fmt.Printf("✓ Connection timeout: %d seconds\n", poolConfig.Timeout)

	// Best Practice 5: Error handling and logging
	fmt.Println("\n--- Error Handling ---")
	fmt.Println("✓ Handle connection failures gracefully")
	fmt.Println("✓ Implement retry logic with exponential backoff")
	fmt.Println("✓ Log authentication attempts for security monitoring")
	fmt.Println("✓ Don't expose sensitive information in error messages")

	// Best Practice 6: Group synchronization
	fmt.Println("\n--- Group Synchronization ---")
	groupSyncConfig := &LDAPGroupSyncConfig{
		Enabled:      true,
		SyncInterval: 3600,    // Sync every hour
		AutoCreate:   false,   // Don't auto-create roles
		RolePrefix:   "LDAP_", // Prefix for LDAP-sourced roles
	}
	fmt.Printf("✓ Sync interval: %d seconds\n", groupSyncConfig.SyncInterval)
	fmt.Printf("✓ Auto-create roles: %t\n", groupSyncConfig.AutoCreate)
	fmt.Printf("✓ Role prefix: %s\n", groupSyncConfig.RolePrefix)
}
