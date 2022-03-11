package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
)

// Algorithm represents a type of private key algorithm.
type Algorithm string

const (
	RSA     Algorithm = "RSA"
	ECDSA   Algorithm = "ECDSA"
	ED25519 Algorithm = "ED25519"
)

func (a Algorithm) String() string {
	return string(a)
}

// SupportedAlgorithms returns a slice of Algorithm currently supported by this provider.
func SupportedAlgorithms() []Algorithm {
	return []Algorithm{
		RSA,
		ECDSA,
		ED25519,
	}
}

// SupportedAlgorithmsStr returns the same content of SupportedAlgorithms but as a slice of string.
func SupportedAlgorithmsStr() []string {
	supported := SupportedAlgorithms()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = string(supported[i])
	}
	return supportedStr
}

// PrivateKeyToAlgorithm identifies the Algorithm used by a given crypto.PrivateKey.
func PrivateKeyToAlgorithm(prvKey crypto.PrivateKey) (Algorithm, error) {
	switch k := prvKey.(type) {
	case *rsa.PrivateKey:
		return RSA, nil
	case *ecdsa.PrivateKey:
		return ECDSA, nil
	case *ed25519.PrivateKey:
		return ED25519, nil
	default:
		return "", fmt.Errorf("failed to identify key algorithm for unsupported private key: %#v", k)
	}
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

// SupportedECDSACurves returns an array of ECDSACurve currently supported by this provider.
func SupportedECDSACurves() []ECDSACurve {
	return []ECDSACurve{
		P224,
		P256,
		P384,
		P521,
	}
}

// SupportedECDSACurvesStr returns the same content of SupportedECDSACurves but as a slice of string.
func SupportedECDSACurvesStr() []string {
	supported := SupportedECDSACurves()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = string(supported[i])
	}
	return supportedStr
}

// PEMPreamblePrivateKey represents the "type" heading used by a PEM-formatted Private Key.
// See: https://datatracker.ietf.org/doc/html/rfc1421
type PEMPreamblePrivateKey string

const (
	PrivateKeyRSA     PEMPreamblePrivateKey = "RSA PRIVATE KEY"
	PrivateKeyECDSA   PEMPreamblePrivateKey = "EC PRIVATE KEY"
	PrivateKeyED25519 PEMPreamblePrivateKey = "PRIVATE KEY"
)

func (p PEMPreamblePrivateKey) String() string {
	return string(p)
}

func (p PEMPreamblePrivateKey) Algorithm() (Algorithm, error) {
	switch p {
	case PrivateKeyRSA:
		return RSA, nil
	case PrivateKeyECDSA:
		return ECDSA, nil
	case PrivateKeyED25519:
		return ED25519, nil
	default:
		return "", fmt.Errorf("unknown PEM preamble for private key: %#v", p)
	}
}

// PEMPreamblePublicKey represents the "type" heading used by a PEM-formatted Public Key.
// See: https://datatracker.ietf.org/doc/html/rfc1421
type PEMPreamblePublicKey string

const (
	PublicKey PEMPreamblePrivateKey = "PUBLIC KEY"
)

func (p PEMPreamblePublicKey) String() string {
	return string(p)
}
