package sso

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// LDAPClient provides LDAP/Active Directory integration
type LDAPClient struct {
	config *LDAPConfig
	conn   *ldap.Conn
}

// NewLDAPClient creates a new LDAP client
func NewLDAPClient(config *LDAPConfig) (*LDAPClient, error) {
	client := &LDAPClient{
		config: config,
	}

	// Establish connection
	if err := client.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	return client, nil
}

// connect establishes connection to LDAP server
func (c *LDAPClient) connect() error {
	var conn *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)

	if c.config.TLS {
		// Use LDAPS (LDAP over TLS)
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.config.Connection.SkipTLSVerify,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		// Use plain LDAP
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return err
		}

		// Use StartTLS if configured
		if c.config.Connection.StartTLS {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: c.config.Connection.SkipTLSVerify,
			}
			if err := conn.StartTLS(tlsConfig); err != nil {
				conn.Close()
				return fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	if err != nil {
		return err
	}

	// Set connection timeouts
	if c.config.Connection.Timeout > 0 {
		conn.SetTimeout(time.Duration(c.config.Connection.Timeout) * time.Second)
	}

	c.conn = conn
	return nil
}

// Close closes the LDAP connection
func (c *LDAPClient) Close() error {
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
	return nil
}

// bind performs LDAP bind with service account
func (c *LDAPClient) bind() error {
	if c.config.BindDN == "" || c.config.BindPassword == "" {
		// Anonymous bind
		return c.conn.UnauthenticatedBind("")
	}

	// Authenticated bind
	return c.conn.Bind(c.config.BindDN, c.config.BindPassword)
}

// Authenticate authenticates a user against LDAP
func (c *LDAPClient) Authenticate(ctx context.Context, username, password string) (*LDAPResult, error) {
	// First, search for the user to get their DN
	user, err := c.SearchUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("user search failed: %w", err)
	}

	if user == nil {
		return nil, NewLDAPUserNotFoundError(username)
	}

	// Check if user is enabled
	if !user.Enabled {
		return nil, NewLDAPUserDisabledError(username)
	}

	// Try to bind with user credentials
	userConn, err := c.createUserConnection(user.DN, password)
	if err != nil {
		return nil, NewLDAPAuthenticationFailedError(username, err)
	}
	defer userConn.Close()

	// Get user groups
	groups, err := c.GetUserGroups(ctx, user.DN)
	if err != nil {
		// Log error but don't fail authentication
		groups = []string{}
	}

	// Create result
	result := &LDAPResult{
		Username:   user.Username,
		Email:      user.Email,
		Name:       user.DisplayName,
		FirstName:  user.FirstName,
		LastName:   user.LastName,
		Groups:     groups,
		Attributes: user.Attributes,
		DN:         user.DN,
		LastSync:   time.Now().Unix(),
	}

	return result, nil
}

// SearchUser searches for a user in LDAP directory
func (c *LDAPClient) SearchUser(ctx context.Context, username string) (*LDAPUser, error) {
	// Bind with service account
	if err := c.bind(); err != nil {
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	// Build search filter
	filter := c.buildUserFilter(username)

	// Build attribute list
	attributes := c.buildUserAttributes()

	// Perform search
	searchRequest := ldap.NewSearchRequest(
		c.config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, // Size limit - we only want one user
		0, // Time limit
		false,
		filter,
		attributes,
		nil,
	)

	searchResult, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("search failed: %w", err)
	}

	if len(searchResult.Entries) == 0 {
		return nil, nil // User not found
	}

	entry := searchResult.Entries[0]
	user := c.entryToLDAPUser(entry)

	return user, nil
}

// GetUserGroups retrieves groups for a user
func (c *LDAPClient) GetUserGroups(ctx context.Context, userDN string) ([]string, error) {
	// Bind with service account
	if err := c.bind(); err != nil {
		return nil, fmt.Errorf("bind failed: %w", err)
	}

	var groups []string

	// Method 1: Get groups from user's memberOf attribute
	if c.config.Attributes.Groups != "" {
		userGroups, err := c.getUserMemberOfGroups(userDN)
		if err == nil {
			groups = append(groups, userGroups...)
		}
	}

	// Method 2: Search for groups that have this user as a member
	if c.config.GroupSync.Enabled && c.config.GroupSync.GroupBaseDN != "" {
		groupGroups, err := c.searchUserGroups(userDN)
		if err == nil {
			groups = append(groups, groupGroups...)
		}
	}

	// Remove duplicates
	groups = c.removeDuplicateStrings(groups)

	return groups, nil
}

// SyncUser synchronizes user information from LDAP
func (c *LDAPClient) SyncUser(ctx context.Context, username string) (*LDAPSyncResult, error) {
	user, err := c.SearchUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to search user: %w", err)
	}

	if user == nil {
		return nil, NewLDAPUserNotFoundError(username)
	}

	// Get user groups
	groups, err := c.GetUserGroups(ctx, user.DN)
	if err != nil {
		// Log error but continue with sync
		groups = []string{}
	}

	result := &LDAPSyncResult{
		Username:   user.Username,
		Email:      user.Email,
		Name:       user.DisplayName,
		Groups:     groups,
		Attributes: user.Attributes,
		Updated:    true, // Always mark as updated for now
		Changes:    []string{"synced from LDAP"},
		SyncTime:   time.Now().Unix(),
	}

	return result, nil
}

// createUserConnection creates a new connection for user authentication
func (c *LDAPClient) createUserConnection(userDN, password string) (*ldap.Conn, error) {
	var conn *ldap.Conn
	var err error

	address := fmt.Sprintf("%s:%d", c.config.Host, c.config.Port)

	if c.config.TLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: c.config.Connection.SkipTLSVerify,
		}
		conn, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		conn, err = ldap.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		if c.config.Connection.StartTLS {
			tlsConfig := &tls.Config{
				InsecureSkipVerify: c.config.Connection.SkipTLSVerify,
			}
			if err := conn.StartTLS(tlsConfig); err != nil {
				conn.Close()
				return nil, fmt.Errorf("failed to start TLS: %w", err)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	// Set timeouts
	if c.config.Connection.Timeout > 0 {
		conn.SetTimeout(time.Duration(c.config.Connection.Timeout) * time.Second)
	}

	// Bind with user credentials
	if err := conn.Bind(userDN, password); err != nil {
		conn.Close()
		return nil, err
	}

	return conn, nil
}

// buildUserFilter builds LDAP search filter for user
func (c *LDAPClient) buildUserFilter(username string) string {
	if c.config.UserFilter != "" {
		// Replace placeholder with actual username
		return strings.ReplaceAll(c.config.UserFilter, "{username}", ldap.EscapeFilter(username))
	}

	// Default filter for Active Directory
	usernameAttr := c.config.Attributes.Username
	if usernameAttr == "" {
		usernameAttr = "sAMAccountName"
	}

	return fmt.Sprintf("(&(objectClass=user)(%s=%s))", usernameAttr, ldap.EscapeFilter(username))
}

// buildUserAttributes builds list of attributes to retrieve
func (c *LDAPClient) buildUserAttributes() []string {
	attributes := []string{"dn"}

	// Add configured attributes
	if c.config.Attributes.Username != "" {
		attributes = append(attributes, c.config.Attributes.Username)
	}
	if c.config.Attributes.Email != "" {
		attributes = append(attributes, c.config.Attributes.Email)
	}
	if c.config.Attributes.FirstName != "" {
		attributes = append(attributes, c.config.Attributes.FirstName)
	}
	if c.config.Attributes.LastName != "" {
		attributes = append(attributes, c.config.Attributes.LastName)
	}
	if c.config.Attributes.DisplayName != "" {
		attributes = append(attributes, c.config.Attributes.DisplayName)
	}
	if c.config.Attributes.Groups != "" {
		attributes = append(attributes, c.config.Attributes.Groups)
	}
	if c.config.Attributes.Enabled != "" {
		attributes = append(attributes, c.config.Attributes.Enabled)
	}

	// Add default attributes if not configured
	defaultAttrs := []string{"mail", "givenName", "sn", "displayName", "memberOf", "userAccountControl"}
	for _, attr := range defaultAttrs {
		if !c.containsString(attributes, attr) {
			attributes = append(attributes, attr)
		}
	}

	return attributes
}

// // entryToLDAPUser converts LDAP entry to LDAPUser
// func (c *LDAPUser) entryToLDAPUser(entry *ldap.Entry) *LDAPUser {
// 	user := &LDAPUser{
// 		DN:         entry.DN,
// 		Attributes: make(map[string]string),
// 	}

// 	// Extract configured attributes
// 	user.Username = c.getAttributeValue(entry, c.config.Attributes.Username, "sAMAccountName")
// 	user.Email = c.getAttributeValue(entry, c.config.Attributes.Email, "mail")
// 	user.FirstName = c.getAttributeValue(entry, c.config.Attributes.FirstName, "givenName")
// 	user.LastName = c.getAttributeValue(entry, c.config.Attributes.LastName, "sn")
// 	user.DisplayName = c.getAttributeValue(entry, c.config.Attributes.DisplayName, "displayName")

// 	// Check if user is enabled (Active Directory specific)
// 	if c.config.Attributes.Enabled != "" {
// 		enabledValue := c.getAttributeValue(entry, c.config.Attributes.Enabled, "")
// 		user.Enabled = c.isUserEnabled(enabledValue)
// 	} else {
// 		// Check userAccountControl for Active Directory
// 		uacValue := c.getAttributeValue(entry, "userAccountControl", "")
// 		user.Enabled = c.isUserEnabledFromUAC(uacValue)
// 	}

// 	// Store all attributes
// 	for _, attr := range entry.Attributes {
// 		if len(attr.Values) > 0 {
// 			user.Attributes[attr.Name] = attr.Values[0]
// 		}
// 	}

// 	return user
// }

// getAttributeValue gets attribute value with fallback
func (c *LDAPClient) getAttributeValue(entry *ldap.Entry, primary, fallback string) string {
	if primary != "" {
		if values := entry.GetAttributeValues(primary); len(values) > 0 {
			return values[0]
		}
	}
	if fallback != "" {
		if values := entry.GetAttributeValues(fallback); len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// isUserEnabled checks if user is enabled based on attribute value
func (c *LDAPClient) isUserEnabled(value string) bool {
	if value == "" {
		return true // Default to enabled if no value
	}

	// Common enabled values
	enabledValues := []string{"true", "1", "active", "enabled"}
	for _, enabled := range enabledValues {
		if strings.EqualFold(value, enabled) {
			return true
		}
	}

	return false
}

// isUserEnabledFromUAC checks if user is enabled from userAccountControl (Active Directory)
func (c *LDAPClient) isUserEnabledFromUAC(uacValue string) bool {
	if uacValue == "" {
		return true // Default to enabled
	}

	uac, err := strconv.Atoi(uacValue)
	if err != nil {
		return true // Default to enabled if can't parse
	}

	// Check if ACCOUNTDISABLE flag (0x2) is set
	const ACCOUNTDISABLE = 0x2
	return (uac & ACCOUNTDISABLE) == 0
}

// getUserMemberOfGroups gets groups from user's memberOf attribute
func (c *LDAPClient) getUserMemberOfGroups(userDN string) ([]string, error) {
	// Search for the user to get memberOf attribute
	searchRequest := ldap.NewSearchRequest(
		userDN,
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		1,
		0,
		false,
		"(objectClass=*)",
		[]string{c.config.Attributes.Groups},
		nil,
	)

	searchResult, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	if len(searchResult.Entries) == 0 {
		return []string{}, nil
	}

	entry := searchResult.Entries[0]
	groupDNs := entry.GetAttributeValues(c.config.Attributes.Groups)

	// Extract group names from DNs
	var groups []string
	for _, groupDN := range groupDNs {
		groupName := c.extractGroupNameFromDN(groupDN)
		if groupName != "" {
			groups = append(groups, groupName)
		}
	}

	return groups, nil
}

// searchUserGroups searches for groups that contain the user as a member
func (c *LDAPClient) searchUserGroups(userDN string) ([]string, error) {
	if c.config.GroupSync.GroupBaseDN == "" {
		return []string{}, nil
	}

	// Build group search filter
	memberAttr := c.config.GroupSync.MemberAttr
	if memberAttr == "" {
		memberAttr = "member"
	}

	filter := fmt.Sprintf("(&(objectClass=group)(%s=%s))", memberAttr, ldap.EscapeFilter(userDN))
	if c.config.GroupFilter != "" {
		filter = fmt.Sprintf("(&%s%s)", c.config.GroupFilter, filter)
	}

	// Build attributes to retrieve
	groupNameAttr := c.config.GroupSync.GroupNameAttr
	if groupNameAttr == "" {
		groupNameAttr = "cn"
	}

	searchRequest := ldap.NewSearchRequest(
		c.config.GroupSync.GroupBaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, // No size limit
		0, // No time limit
		false,
		filter,
		[]string{groupNameAttr},
		nil,
	)

	searchResult, err := c.conn.Search(searchRequest)
	if err != nil {
		return nil, err
	}

	var groups []string
	for _, entry := range searchResult.Entries {
		groupNames := entry.GetAttributeValues(groupNameAttr)
		if len(groupNames) > 0 {
			groups = append(groups, groupNames[0])
		}
	}

	return groups, nil
}

// extractGroupNameFromDN extracts group name from DN
func (c *LDAPClient) extractGroupNameFromDN(dn string) string {
	// Parse DN to extract CN (Common Name)
	parts := strings.Split(dn, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "cn=") {
			return part[3:] // Remove "cn=" prefix
		}
	}
	return ""
}

// containsString checks if slice contains string
func (c *LDAPClient) containsString(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// removeDuplicateStrings removes duplicate strings from slice
func (c *LDAPClient) removeDuplicateStrings(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
}

// Helper method to fix the entryToLDAPUser method
func (c *LDAPClient) entryToLDAPUser(entry *ldap.Entry) *LDAPUser {
	user := &LDAPUser{
		DN:         entry.DN,
		Attributes: make(map[string]string),
	}

	// Extract configured attributes
	user.Username = c.getAttributeValue(entry, c.config.Attributes.Username, "sAMAccountName")
	user.Email = c.getAttributeValue(entry, c.config.Attributes.Email, "mail")
	user.FirstName = c.getAttributeValue(entry, c.config.Attributes.FirstName, "givenName")
	user.LastName = c.getAttributeValue(entry, c.config.Attributes.LastName, "sn")
	user.DisplayName = c.getAttributeValue(entry, c.config.Attributes.DisplayName, "displayName")

	// Check if user is enabled (Active Directory specific)
	if c.config.Attributes.Enabled != "" {
		enabledValue := c.getAttributeValue(entry, c.config.Attributes.Enabled, "")
		user.Enabled = c.isUserEnabled(enabledValue)
	} else {
		// Check userAccountControl for Active Directory
		uacValue := c.getAttributeValue(entry, "userAccountControl", "")
		user.Enabled = c.isUserEnabledFromUAC(uacValue)
	}

	// Store all attributes
	for _, attr := range entry.Attributes {
		if len(attr.Values) > 0 {
			user.Attributes[attr.Name] = attr.Values[0]
		}
	}

	return user
}
