package provider

// Algorithm represents a type of private key algorithm
type Algorithm string

const (
	RSA     Algorithm = "RSA"
	ECDSA   Algorithm = "ECDSA"
	ED25519 Algorithm = "ED25519"
)

// SupportedAlgorithms returns a slice of Algorithm currently supported by this provider
func SupportedAlgorithms() []Algorithm {
	return []Algorithm{
		RSA,
		ECDSA,
		ED25519,
	}
}

// SupportedAlgorithmsStr returns the same content of SupportedAlgorithms but as a slice of string
func SupportedAlgorithmsStr() []string {
	supported := SupportedAlgorithms()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = string(supported[i])
	}
	return supportedStr
}

// ECDSACurve represents a type of ECDSA elliptic curve
type ECDSACurve string

const (
	P224 ECDSACurve = "P224"
	P256 ECDSACurve = "P256"
	P384 ECDSACurve = "P384"
	P521 ECDSACurve = "P521"
)

// SupportedECDSACurves returns an array of ECDSACurve currently supported by this provider
func SupportedECDSACurves() []ECDSACurve {
	return []ECDSACurve{
		P224,
		P256,
		P384,
		P521,
	}
}

// SupportedECDSACurvesStr returns the same content of SupportedECDSACurves but as a slice of string
func SupportedECDSACurvesStr() []string {
	supported := SupportedECDSACurves()
	supportedStr := make([]string, len(supported))
	for i := range supported {
		supportedStr[i] = string(supported[i])
	}
	return supportedStr
}
