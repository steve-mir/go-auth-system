package sso

import "encoding/xml"

// SAML XML structures for parsing and generating SAML documents

// EntityDescriptor represents SAML metadata
type EntityDescriptor struct {
	XMLName          xml.Name          `xml:"urn:oasis:names:tc:SAML:2.0:metadata EntityDescriptor"`
	EntityID         string            `xml:"entityID,attr"`
	SPSSODescriptor  *SPSSODescriptor  `xml:"SPSSODescriptor,omitempty"`
	IDPSSODescriptor *IDPSSODescriptor `xml:"IDPSSODescriptor,omitempty"`
}

// SPSSODescriptor represents Service Provider SSO descriptor
type SPSSODescriptor struct {
	XMLName                    xml.Name                   `xml:"urn:oasis:names:tc:SAML:2.0:metadata SPSSODescriptor"`
	AuthnRequestsSigned        bool                       `xml:"AuthnRequestsSigned,attr"`
	WantAssertionsSigned       bool                       `xml:"WantAssertionsSigned,attr"`
	ProtocolSupportEnumeration string                     `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              []KeyDescriptor            `xml:"KeyDescriptor"`
	NameIDFormat               []string                   `xml:"NameIDFormat"`
	AssertionConsumerService   []AssertionConsumerService `xml:"AssertionConsumerService"`
	SingleLogoutService        []SingleLogoutService      `xml:"SingleLogoutService,omitempty"`
}

// IDPSSODescriptor represents Identity Provider SSO descriptor
type IDPSSODescriptor struct {
	XMLName                    xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:metadata IDPSSODescriptor"`
	WantAuthnRequestsSigned    bool                  `xml:"WantAuthnRequestsSigned,attr"`
	ProtocolSupportEnumeration string                `xml:"protocolSupportEnumeration,attr"`
	KeyDescriptor              []KeyDescriptor       `xml:"KeyDescriptor"`
	NameIDFormat               []string              `xml:"NameIDFormat"`
	SingleSignOnService        []SingleSignOnService `xml:"SingleSignOnService"`
	SingleLogoutService        []SingleLogoutService `xml:"SingleLogoutService,omitempty"`
}

// KeyDescriptor represents key descriptor in metadata
type KeyDescriptor struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata KeyDescriptor"`
	Use     string   `xml:"use,attr,omitempty"`
	KeyInfo KeyInfo  `xml:"KeyInfo"`
}

// KeyInfo represents key information
type KeyInfo struct {
	XMLName  xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# KeyInfo"`
	X509Data X509Data `xml:"X509Data"`
}

// X509Data represents X509 certificate data
type X509Data struct {
	XMLName         xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# X509Data"`
	X509Certificate string   `xml:"X509Certificate"`
}

// AssertionConsumerService represents assertion consumer service
type AssertionConsumerService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata AssertionConsumerService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
	Index    int      `xml:"index,attr"`
}

// SingleSignOnService represents single sign-on service
type SingleSignOnService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleSignOnService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// SingleLogoutService represents single logout service
type SingleLogoutService struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:metadata SingleLogoutService"`
	Binding  string   `xml:"Binding,attr"`
	Location string   `xml:"Location,attr"`
}

// AuthnRequest represents SAML authentication request
type AuthnRequest struct {
	XMLName                     xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:protocol AuthnRequest"`
	ID                          string                `xml:"ID,attr"`
	Version                     string                `xml:"Version,attr"`
	IssueInstant                string                `xml:"IssueInstant,attr"`
	Destination                 string                `xml:"Destination,attr"`
	AssertionConsumerServiceURL string                `xml:"AssertionConsumerServiceURL,attr"`
	ProtocolBinding             string                `xml:"ProtocolBinding,attr"`
	Issuer                      Issuer                `xml:"Issuer"`
	NameIDPolicy                NameIDPolicy          `xml:"NameIDPolicy"`
	RequestedAuthnContext       RequestedAuthnContext `xml:"RequestedAuthnContext"`
}

// Response represents SAML response
type Response struct {
	XMLName      xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:protocol Response"`
	ID           string      `xml:"ID,attr"`
	Version      string      `xml:"Version,attr"`
	IssueInstant string      `xml:"IssueInstant,attr"`
	Destination  string      `xml:"Destination,attr"`
	InResponseTo string      `xml:"InResponseTo,attr"`
	Issuer       Issuer      `xml:"Issuer"`
	Status       Status      `xml:"Status"`
	Assertion    []Assertion `xml:"Assertion"`
	Signature    *Signature  `xml:"Signature,omitempty"`
}

// Assertion represents SAML assertion
type Assertion struct {
	XMLName            xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string              `xml:"ID,attr"`
	Version            string              `xml:"Version,attr"`
	IssueInstant       string              `xml:"IssueInstant,attr"`
	Issuer             Issuer              `xml:"Issuer"`
	Subject            Subject             `xml:"Subject"`
	Conditions         Conditions          `xml:"Conditions"`
	AuthnStatement     []AuthnStatement    `xml:"AuthnStatement"`
	AttributeStatement *AttributeStatement `xml:"AttributeStatement,omitempty"`
	Signature          *Signature          `xml:"Signature,omitempty"`
}

// Issuer represents SAML issuer
type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Value   string   `xml:",chardata"`
}

// Subject represents SAML subject
type Subject struct {
	XMLName             xml.Name            `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              NameID              `xml:"NameID"`
	SubjectConfirmation SubjectConfirmation `xml:"SubjectConfirmation"`
}

// NameID represents SAML NameID
type NameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format  string   `xml:"Format,attr,omitempty"`
	Value   string   `xml:",chardata"`
}

// NameIDPolicy represents SAML NameID policy
type NameIDPolicy struct {
	XMLName     xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol NameIDPolicy"`
	Format      string   `xml:"Format,attr,omitempty"`
	AllowCreate bool     `xml:"AllowCreate,attr,omitempty"`
}

// SubjectConfirmation represents SAML subject confirmation
type SubjectConfirmation struct {
	XMLName                 xml.Name                `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                  string                  `xml:"Method,attr"`
	SubjectConfirmationData SubjectConfirmationData `xml:"SubjectConfirmationData"`
}

// SubjectConfirmationData represents SAML subject confirmation data
type SubjectConfirmationData struct {
	XMLName      xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	NotOnOrAfter string   `xml:"NotOnOrAfter,attr,omitempty"`
	Recipient    string   `xml:"Recipient,attr,omitempty"`
	InResponseTo string   `xml:"InResponseTo,attr,omitempty"`
}

// Conditions represents SAML conditions
type Conditions struct {
	XMLName             xml.Name              `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore           string                `xml:"NotBefore,attr,omitempty"`
	NotOnOrAfter        string                `xml:"NotOnOrAfter,attr,omitempty"`
	AudienceRestriction []AudienceRestriction `xml:"AudienceRestriction"`
}

// AudienceRestriction represents SAML audience restriction
type AudienceRestriction struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience []string `xml:"Audience"`
}

// AuthnStatement represents SAML authentication statement
type AuthnStatement struct {
	XMLName      xml.Name     `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AuthnInstant string       `xml:"AuthnInstant,attr"`
	SessionIndex string       `xml:"SessionIndex,attr,omitempty"`
	AuthnContext AuthnContext `xml:"AuthnContext"`
}

// AuthnContext represents SAML authentication context
type AuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
	AuthnContextClassRef string   `xml:"AuthnContextClassRef"`
}

// RequestedAuthnContext represents requested authentication context
type RequestedAuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol RequestedAuthnContext"`
	Comparison           string   `xml:"Comparison,attr"`
	AuthnContextClassRef []string `xml:"AuthnContextClassRef"`
}

// AttributeStatement represents SAML attribute statement
type AttributeStatement struct {
	XMLName   xml.Name    `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attribute []Attribute `xml:"Attribute"`
}

// Attribute represents SAML attribute
type Attribute struct {
	XMLName        xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	Name           string   `xml:"Name,attr"`
	NameFormat     string   `xml:"NameFormat,attr,omitempty"`
	AttributeValue []string `xml:"AttributeValue"`
}

// Status represents SAML status
type Status struct {
	XMLName    xml.Name   `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	StatusCode StatusCode `xml:"StatusCode"`
}

// StatusCode represents SAML status code
type StatusCode struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:protocol StatusCode"`
	Value   string   `xml:"Value,attr"`
}

// Signature represents XML signature
type Signature struct {
	XMLName        xml.Name       `xml:"http://www.w3.org/2000/09/xmldsig# Signature"`
	SignedInfo     SignedInfo     `xml:"SignedInfo"`
	SignatureValue SignatureValue `xml:"SignatureValue"`
	KeyInfo        KeyInfo        `xml:"KeyInfo"`
}

// SignedInfo represents signed info in XML signature
type SignedInfo struct {
	XMLName                xml.Name               `xml:"http://www.w3.org/2000/09/xmldsig# SignedInfo"`
	CanonicalizationMethod CanonicalizationMethod `xml:"CanonicalizationMethod"`
	SignatureMethod        SignatureMethod        `xml:"SignatureMethod"`
	Reference              Reference              `xml:"Reference"`
}

// CanonicalizationMethod represents canonicalization method
type CanonicalizationMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# CanonicalizationMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// SignatureMethod represents signature method
type SignatureMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// Reference represents reference in XML signature
type Reference struct {
	XMLName      xml.Name     `xml:"http://www.w3.org/2000/09/xmldsig# Reference"`
	URI          string       `xml:"URI,attr"`
	Transforms   Transforms   `xml:"Transforms"`
	DigestMethod DigestMethod `xml:"DigestMethod"`
	DigestValue  string       `xml:"DigestValue"`
}

// Transforms represents transforms in XML signature
type Transforms struct {
	XMLName   xml.Name    `xml:"http://www.w3.org/2000/09/xmldsig# Transforms"`
	Transform []Transform `xml:"Transform"`
}

// Transform represents transform in XML signature
type Transform struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# Transform"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// DigestMethod represents digest method
type DigestMethod struct {
	XMLName   xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# DigestMethod"`
	Algorithm string   `xml:"Algorithm,attr"`
}

// SignatureValue represents signature value
type SignatureValue struct {
	XMLName xml.Name `xml:"http://www.w3.org/2000/09/xmldsig# SignatureValue"`
	Value   string   `xml:",chardata"`
}
