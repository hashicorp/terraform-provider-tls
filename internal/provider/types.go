// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// PrivateKeyAlgorithm represents a type of private key algorithm.
type PrivateKeyAlgorithm string

const (
	RSA     PrivateKeyAlgorithm = "RSA"
	ECDSA   PrivateKeyAlgorithm = "ECDSA"
	ED25519 PrivateKeyAlgorithm = "ED25519"
)

func (a PrivateKeyAlgorithm) String() string {
	return string(a)
}

// supportedPrivateKeyAlgorithms returns a slice of private key algorithm currently supported by this provider.
func supportedPrivateKeyAlgorithms() []PrivateKeyAlgorithm {
	return []PrivateKeyAlgorithm{
		RSA,
		ECDSA,
		ED25519,
	}
}

// supportedPrivateKeyAlgorithmsStr returns the same content of supportedPrivateKeyAlgorithms but as a slice of string.
func supportedPrivateKeyAlgorithmsStr() []string {
	supported := supportedPrivateKeyAlgorithms()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = supported[i].String()
	}
	return supportedStr
}

// supportedSignatureAlgorithms returns a slice of signature algorithm currently supported by this provider.
func supportedSignatureAlgorithms() []x509.SignatureAlgorithm {
	return []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
		x509.PureEd25519,
	}
}

// supportedSignatureAlgorithmsStr returns the same content of supportedSignatureAlgorithms but as a slice of string.
func supportedSignatureAlgorithmsStr() []string {
	supported := supportedSignatureAlgorithms()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = supported[i].String()
	}
	return supportedStr
}

// ECDSACurve represents a type of ECDSA elliptic curve.
type ECDSACurve string

const (
	P224 ECDSACurve = "P224"
	P256 ECDSACurve = "P256"
	P384 ECDSACurve = "P384"
	P521 ECDSACurve = "P521"
)

func (e ECDSACurve) String() string {
	return string(e)
}

// supportedECDSACurves returns an array of ECDSACurve currently supported by this provider.
func supportedECDSACurves() []ECDSACurve {
	return []ECDSACurve{
		P224,
		P256,
		P384,
		P521,
	}
}

// supportedECDSACurvesStr returns the same content of supportedECDSACurves but as a slice of string.
func supportedECDSACurvesStr() []string {
	supported := supportedECDSACurves()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = supported[i].String()
	}
	return supportedStr
}

// PEMPreamble represents the heading used in a PEM-formatted for the "encapsulation boundaries",
// that is used to delimit the "encapsulated text portion" of cryptographic documents.
//
// See https://datatracker.ietf.org/doc/html/rfc1421 and https://datatracker.ietf.org/doc/html/rfc7468.
type PEMPreamble string

const (
	PreamblePublicKey PEMPreamble = "PUBLIC KEY"

	PreamblePrivateKeyPKCS8   PEMPreamble = "PRIVATE KEY"
	PreamblePrivateKeyRSA     PEMPreamble = "RSA PRIVATE KEY"
	PreamblePrivateKeyEC      PEMPreamble = "EC PRIVATE KEY"
	PreamblePrivateKeyOpenSSH PEMPreamble = "OPENSSH PRIVATE KEY"

	PreambleCertificate        PEMPreamble = "CERTIFICATE"
	PreambleCertificateRequest PEMPreamble = "CERTIFICATE REQUEST"
)

func (p PEMPreamble) String() string {
	return string(p)
}

// pemBlockToPEMPreamble takes a pem.Block and returns the related PEMPreamble, if supported.
func pemBlockToPEMPreamble(block *pem.Block) (PEMPreamble, error) {
	switch block.Type {
	case PreamblePublicKey.String():
		return PreamblePublicKey, nil
	case PreamblePrivateKeyPKCS8.String():
		return PreamblePrivateKeyPKCS8, nil
	case PreamblePrivateKeyRSA.String():
		return PreamblePrivateKeyRSA, nil
	case PreamblePrivateKeyEC.String():
		return PreamblePrivateKeyEC, nil
	case PreambleCertificate.String():
		return PreambleCertificate, nil
	case PreambleCertificateRequest.String():
		return PreambleCertificateRequest, nil
	default:
		return "", fmt.Errorf("unsupported PEM preamble/type: %s", block.Type)
	}
}

// ProxyScheme represents url schemes supported when providing proxy configuration to this provider.
type ProxyScheme string

const (
	HTTPProxy   ProxyScheme = "http"
	HTTPSProxy  ProxyScheme = "https"
	SOCKS5Proxy ProxyScheme = "socks5"
)

func (p ProxyScheme) String() string {
	return string(p)
}

// supportedProxySchemes returns an array of ProxyScheme currently supported by this provider.
func supportedProxySchemes() []ProxyScheme {
	return []ProxyScheme{
		HTTPProxy,
		HTTPSProxy,
		SOCKS5Proxy,
	}
}

// supportedProxySchemesStr returns the same content of supportedProxySchemes but as a slice of string.
func supportedProxySchemesStr() []string {
	supported := supportedProxySchemes()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = string(supported[i])
	}
	return supportedStr
}

// URLScheme represents url schemes supported by resources and data-sources of this provider.
type URLScheme string

const (
	HTTPSScheme URLScheme = "https"
	TLSScheme   URLScheme = "tls"
)

func (p URLScheme) String() string {
	return string(p)
}

// supportedURLSchemes returns an array of URLScheme currently supported by this provider.
func supportedURLSchemes() []URLScheme {
	return []URLScheme{
		HTTPSScheme,
		TLSScheme,
	}
}

// supportedURLSchemesStr returns the same content of supportedURLSchemes but as a slice of string.
func supportedURLSchemesStr() []string {
	supported := supportedURLSchemes()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = string(supported[i])
	}
	return supportedStr
}
