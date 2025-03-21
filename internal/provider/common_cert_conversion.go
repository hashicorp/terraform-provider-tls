// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
	"crypto/dsa"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const (
	BlockPublicKey            = "PUBLIC KEY"
	BlockPrivateKey           = "PRIVATE KEY"
	BlockEncryptedPrivateKey  = "ENCRYPTED PRIVATE KEY"
	BlockRSAPublicKey         = "RSA PUBLIC KEY"
	BlockRSAPrivateKey        = "RSA PRIVATE KEY"
	BlockECPrivateKey         = "EC PRIVATE KEY"
	BlockDSAPublicKey         = "DSA PUBLIC KEY"
	BlockDSAPrivateKey        = "DSA PRIVATE KEY"
	BlockOpenSshPrivateKey    = "OPENSSH PRIVATE KEY"
	BlockCertificate          = "CERTIFICATE"
	BlockEncryptedCertificate = "ENCRYPTED CERTIFICATE"
	BlockCertificateRequest   = "CERTIFICATE REQUEST"
)

// MarshalPrivateKey serializes a private key into bytes.
//
// Supported Formats:
// - Legacy (true):
//   - **RSA**: PKCS #1 (ASN.1 DER).
//   - **ECDSA**: SEC1 (ASN.1 DER).
//
// - Modern (false):
//   - **RSA**, **ECDSA**, and **Ed25519**: PKCS #8 (ASN.1 DER).
//
// Parameters:
// - key: The private key to serialize. Must be of type *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey.
// - legacy: If true, serializes to a legacy format (PKCS #1 or SEC1). If false, uses the modern PKCS #8 format.
//
// Returns:
// - Serialized key as a byte slice.
// - An error if the key type is unsupported or serialization fails.
func MarshalPrivateKey(key any, legacy bool) ([]byte, error) {
	if legacy {
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			return x509.MarshalECPrivateKey(k)
		case *rsa.PrivateKey:
			return x509.MarshalPKCS1PrivateKey(k), nil
		case *ecdh.PrivateKey:
			return x509.MarshalPKCS8PrivateKey(k)
		case ed25519.PrivateKey:
			return x509.MarshalPKCS8PrivateKey(k)
		case *dsa.PrivateKey:
			return MarshalDSAPrivateKey(k)
		default:
			return nil, fmt.Errorf("Unsupported private key type: %v", k)
		}
	} else {
		switch k := key.(type) {
		case *dsa.PrivateKey:
			return MarshalDSAPrivateKey(k)
		default:
			// Use PKCS #8 for all key types
			return x509.MarshalPKCS8PrivateKey(key)
		}
	}
}

func MarshalPrivateKeyToPEM(key any, legacy bool) (*pem.Block, error) {
	var keyBytes []byte
	var err error

	if legacy {
		switch k := key.(type) {
		case *ecdsa.PrivateKey:
			keyBytes, err = x509.MarshalECPrivateKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
			}
			return &pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: keyBytes,
			}, nil

		case *rsa.PrivateKey:
			keyBytes = x509.MarshalPKCS1PrivateKey(k)
			return &pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: keyBytes,
			}, nil

		case *ecdh.PrivateKey:
			keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ECDH private key: %v", err)
			}
			return &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			}, nil

		case ed25519.PrivateKey:
			keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Ed25519 private key: %v", err)
			}
			return &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			}, nil

		case *dsa.PrivateKey:
			keyBytes, err = MarshalDSAPrivateKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal DSA private key: %v", err)
			}
			return &pem.Block{
				Type:  "DSA PRIVATE KEY",
				Bytes: keyBytes,
			}, nil

		default:
			return nil, fmt.Errorf("unsupported private key type: %T", k)
		}
	} else {
		switch k := key.(type) {
		case *dsa.PrivateKey:
			keyBytes, err = MarshalDSAPrivateKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal DSA private key: %v", err)
			}
			return &pem.Block{
				Type:  "DSA PRIVATE KEY",
				Bytes: keyBytes,
			}, nil

		default:
			// Use PKCS #8 for all key types
			keyBytes, err = x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal private key to PKCS8: %v", err)
			}
			return &pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			}, nil
		}
	}
}

// ParsePrivateKey deserializes a private key from bytes.
//
// Supported Formats (in order of parsing):
// 1. PKCS #8 (ASN.1 DER): Supports RSA, ECDSA, and Ed25519 keys.
// 2. PKCS #1 (ASN.1 DER): Supports RSA keys only.
// 3. SEC1 (ASN.1 DER): Supports ECDSA keys only.
//
// Parameters:
// - data: The serialized private key in one of the supported formats.
//
// Returns:
// - The deserialized private key as an interface{} of type *rsa.PrivateKey, *ecdsa.PrivateKey, or ed25519.PrivateKey.
// - An error if the data is not in a recognized format or deserialization fails.
func ParsePrivateKey(data []byte) (any, error) {
	// Attempt to parse as PKCS8
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		return key, nil
	}

	// Attempt to parse as PKCS1 (RSA only)
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return key, nil
	}

	// Attempt to parse as SEC1 (ECDSA only)
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return key, nil
	}

	// Attempt to parse as SEC1 (DSA only)
	if key, err := ParseDSAPrivateKey(data); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key (tried PKCS8, PKCS1, and SEC1)")
}

// MarshalPublicKey serializes a public key into bytes.
//
// Supported Formats:
// - Legacy (true): PKCS #1 (ASN.1 DER) for RSA public keys.
// - Modern (false): PKIX (ASN.1 DER), the standard format for public keys.
//
// Parameters:
// - key: The public key to serialize. Must be of type *rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey.
// - legacy: If true, uses PKCS #1 format (only for RSA public keys). Otherwise, uses PKIX format.
//
// Returns:
// - Serialized key as a byte slice.
// - An error if the key type is unsupported or serialization fails.
func MarshalPublicKey(key any, legacy bool) ([]byte, error) {
	if legacy {
		switch k := key.(type) {
		case *rsa.PublicKey:
			return x509.MarshalPKCS1PublicKey(k), nil
		case *ecdsa.PrivateKey:
			return x509.MarshalPKIXPublicKey(k)
		case *ecdh.PrivateKey:
			return x509.MarshalPKIXPublicKey(k)
		case ed25519.PrivateKey:
			return x509.MarshalPKIXPublicKey(k)
		case *dsa.PublicKey:
			return MarshalDSAPublicKey(k)
		default:
			return nil, fmt.Errorf("Unsupported public key type: %v", k)
		}
	}
	return x509.MarshalPKIXPublicKey(key)
}

// ParsePublicKey deserializes a public key from bytes.
//
// Supported Formats (in order of parsing):
// 1. PKIX (ASN.1 DER): General format for RSA, ECDSA, and Ed25519 keys.
// 2. PKCS #1 (ASN.1 DER): Specific format for RSA public keys.
//
// Parameters:
// - data: The serialized public key in PKIX or PKCS #1 format.
//
// Returns:
// - The deserialized public key as an interface{} of type *rsa.PublicKey, *ecdsa.PublicKey, or ed25519.PublicKey.
// - An error if the data is not in a recognized format or deserialization fails.
func ParsePublicKey(data []byte) (any, error) {
	// Attempt to parse as PKIX
	if key, err := x509.ParsePKIXPublicKey(data); err == nil {
		return key, nil
	}

	// Attempt to parse as PKCS1 (RSA only)
	if key, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse public key (tried PKIX and PKCS1)")
}

func ParsePem(pemData []byte, password string, legacy bool) (privateKeys []any, publicKeys []any, certificates []*x509.Certificate, certificateRequests []*x509.CertificateRequest, err error) {
	// Read and process all PEM blocks
	for {
		var blockBytes []byte
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}

		//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
		if x509.IsEncryptedPEMBlock(block) {
			//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
			blockBytes, err = x509.DecryptPEMBlock(block, []byte(password))
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to decrypt private key: %v", err)
			}
		} else {
			blockBytes = block.Bytes
		}

		switch block.Type {
		case BlockEncryptedPrivateKey:
			// Attempt to parse as PKCS8, then PKCS1 and then finally EC
			// It returns *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey (not a pointer), *ecdh.PrivateKey
			var privateKey any
			var errPKCS8 error
			privateKey, errPKCS8 = x509.ParsePKCS8PrivateKey(blockBytes)
			if err != nil {
				privateKey, err = x509.ParsePKCS1PrivateKey(blockBytes)
				if err == nil {
					errPKCS8 = nil
				} else {
					privateKey, err = x509.ParseECPrivateKey(blockBytes)
					if err == nil {
						errPKCS8 = nil
					}
				}
			}

			if errPKCS8 != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse PKCS8 private key: %v", err)
			}

			privateKeys = append(privateKeys, privateKey)
		case BlockPrivateKey:
			// Attempt to parse as PKCS8, then PKCS1 and then finally EC
			// It returns *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey (not a pointer), *ecdh.PrivateKey
			var privateKey any
			var errPKCS8 error
			privateKey, errPKCS8 = x509.ParsePKCS8PrivateKey(blockBytes)
			if err != nil {
				privateKey, err = x509.ParsePKCS1PrivateKey(blockBytes)
				if err == nil {
					errPKCS8 = nil
				} else {
					privateKey, err = x509.ParseECPrivateKey(blockBytes)
					if err == nil {
						errPKCS8 = nil
						privateKey, err = ParseDSAPrivateKey(blockBytes)
						if err == nil {
							errPKCS8 = nil
						}
					}
				}
			}

			if errPKCS8 != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse PKCS8 private key: %v", err)
			}

			privateKeys = append(privateKeys, privateKey)
		case BlockRSAPrivateKey:
			// Attempt to parse as PKCS1 (RSA only)
			// It returns *rsa.PrivateKey
			var privateKey any
			privateKey, err = x509.ParsePKCS1PrivateKey(blockBytes)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse PKCS1 private key: %v", err)
			}
			privateKeys = append(privateKeys, privateKey)
		case BlockECPrivateKey:
			// Attempt to parse as SEC1 (ECDSA only)
			// It returns *ecdsa.PrivateKey
			var privateKey any
			privateKey, err = x509.ParseECPrivateKey(blockBytes)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse SEC1 private key: %v", err)
			}
			privateKeys = append(privateKeys, privateKey)
		case BlockRSAPublicKey:
			// Attempt to parse as PKCS (RSA only)
			// It returns *rsa.PublicKey
			var publicKey any
			publicKey, err = x509.ParsePKCS1PublicKey(blockBytes)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse PKCS private key: %v", err)
			}
			publicKeys = append(publicKeys, publicKey)
		case BlockDSAPublicKey:
			// Attempt to parse as PKIX
			// It returns a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey (not a pointer), *ecdh.PublicKey (for X25519)
			var publicKey any
			publicKey, err = x509.ParsePKIXPublicKey(blockBytes)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse PKIX private key: %v", err)
			}
			publicKeys = append(publicKeys, publicKey)
		case BlockPublicKey:
			// Attempt to parse as PKIX
			// It returns a *rsa.PublicKey, *dsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey (not a pointer), *ecdh.PublicKey (for X25519)
			var publicKey any
			publicKey, err = x509.ParsePKIXPublicKey(blockBytes)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse PKIX private key: %v", err)
			}
			publicKeys = append(publicKeys, publicKey)
		case BlockEncryptedCertificate:
			var certificate *x509.Certificate
			certificate, err = x509.ParseCertificate(blockBytes)

			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			certificates = append(certificates, certificate)
		case BlockCertificate:
			var certificate *x509.Certificate
			certificate, err = x509.ParseCertificate(blockBytes)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse certificate: %v", err)
			}
			certificates = append(certificates, certificate)
		case BlockCertificateRequest:
			var certificateRequest *x509.CertificateRequest
			certificateRequest, err = x509.ParseCertificateRequest(blockBytes)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("failed to parse certificate request: %v", err)
			}
			certificateRequests = append(certificateRequests, certificateRequest)
		}

		// Process remaining PEM data
		pemData = rest
	}

	return privateKeys, publicKeys, certificates, certificateRequests, nil
}

func MarshalPem(privateKeys []any, publicKeys []any, certificates []*x509.Certificate, certificateRequests []*x509.CertificateRequest, password string, encryptCertificate bool, legacy bool) (pemData []byte, err error) {
	pemBlocks := make([]*pem.Block, 0)

	for _, privateKey := range privateKeys {
		// Marshal the key into ASN.1 DER format
		switch k := privateKey.(type) {
		case *rsa.PrivateKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			if legacy {
				keyBytes = x509.MarshalPKCS1PrivateKey(k)

				pemBlock = &pem.Block{
					Type:  BlockRSAPublicKey,
					Bytes: keyBytes,
				}
			} else {
				keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal RSA private key: %w", err)
				}

				if len(password) > 0 {
					randomReader := rand.Reader
					//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
					pemBlock, err = x509.EncryptPEMBlock(randomReader, BlockPrivateKey, keyBytes, []byte(password), x509.PEMCipherAES256)
					if err != nil {
						return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
					}
				} else {
					pemBlock = &pem.Block{
						Type:  BlockPrivateKey,
						Bytes: keyBytes,
					}
				}
			}
			pemBlocks = append(pemBlocks, pemBlock)
		case *ecdsa.PrivateKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			if legacy {
				keyBytes, err = x509.MarshalECPrivateKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
				}

				pemBlock = &pem.Block{
					Type:  BlockECPrivateKey,
					Bytes: keyBytes,
				}
			} else {
				keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
				}

				if len(password) > 0 {
					randomReader := rand.Reader
					//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
					pemBlock, err = x509.EncryptPEMBlock(randomReader, BlockPrivateKey, keyBytes, []byte(password), x509.PEMCipherAES256)
					if err != nil {
						return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
					}
				} else {
					pemBlock = &pem.Block{
						Type:  BlockPrivateKey,
						Bytes: keyBytes,
					}
				}
			}
			pemBlocks = append(pemBlocks, pemBlock)
		case *ecdh.PrivateKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ECDH private key: %w", err)
			}

			if len(password) > 0 {
				randomReader := rand.Reader
				//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
				pemBlock, err = x509.EncryptPEMBlock(randomReader, BlockPrivateKey, keyBytes, []byte(password), x509.PEMCipherAES256)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
				}
			} else {
				pemBlock = &pem.Block{
					Type:  BlockPrivateKey,
					Bytes: keyBytes,
				}
			}

			pemBlocks = append(pemBlocks, pemBlock)
		case ed25519.PrivateKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			keyBytes, err = x509.MarshalPKCS8PrivateKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Ed25519 private key: %w", err)
			}

			if len(password) > 0 {
				randomReader := rand.Reader
				//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
				pemBlock, err = x509.EncryptPEMBlock(randomReader, BlockPrivateKey, keyBytes, []byte(password), x509.PEMCipherAES256)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
				}
			} else {
				pemBlock = &pem.Block{
					Type:  BlockPrivateKey,
					Bytes: keyBytes,
				}
			}
			pemBlocks = append(pemBlocks, pemBlock)
		case *dsa.PrivateKey:
			var keyBytes []byte
			var pemBlock *pem.Block
			//TODO: Should marshal be the same for both
			if legacy {
				keyBytes, err = MarshalDSAPrivateKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal DSA private key: %w", err)
				}

				if len(password) > 0 {
					randomReader := rand.Reader
					//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
					pemBlock, err = x509.EncryptPEMBlock(randomReader, BlockPrivateKey, keyBytes, []byte(password), x509.PEMCipherAES256)
					if err != nil {
						return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
					}
				} else {
					pemBlock = &pem.Block{
						Type:  BlockDSAPrivateKey,
						Bytes: keyBytes,
					}
				}
			} else {
				keyBytes, err = MarshalDSAPrivateKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal DSA private key: %w", err)
				}

				if len(password) > 0 {
					randomReader := rand.Reader
					//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
					pemBlock, err = x509.EncryptPEMBlock(randomReader, BlockPrivateKey, keyBytes, []byte(password), x509.PEMCipherAES256)
					if err != nil {
						return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
					}
				} else {
					pemBlock = &pem.Block{
						Type:  BlockPrivateKey,
						Bytes: keyBytes,
					}
				}
			}

			pemBlocks = append(pemBlocks, pemBlock)
		default:
			return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
		}
	}

	for _, publicKey := range publicKeys {
		switch k := publicKey.(type) {
		case *rsa.PublicKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			if legacy {
				keyBytes = x509.MarshalPKCS1PublicKey(k)

				pemBlock = &pem.Block{
					Type:  BlockRSAPublicKey,
					Bytes: keyBytes,
				}
			} else {
				keyBytes, err = x509.MarshalPKIXPublicKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal RSA public key: %w", err)
				}

				pemBlock = &pem.Block{
					Type:  BlockPublicKey,
					Bytes: keyBytes,
				}
			}

			pemBlocks = append(pemBlocks, pemBlock)
		case *ecdsa.PublicKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			keyBytes, err = x509.MarshalPKIXPublicKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ECDSA public key: %w", err)
			}

			pemBlock = &pem.Block{
				Type:  BlockPublicKey,
				Bytes: keyBytes,
			}

			pemBlocks = append(pemBlocks, pemBlock)
		case *ecdh.PublicKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			keyBytes, err = x509.MarshalPKIXPublicKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal ECDH public key: %w", err)
			}

			pemBlock = &pem.Block{
				Type:  BlockPublicKey,
				Bytes: keyBytes,
			}

			pemBlocks = append(pemBlocks, pemBlock)
		case ed25519.PublicKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			keyBytes, err = x509.MarshalPKIXPublicKey(k)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal Ed25519 public key: %w", err)
			}

			pemBlock = &pem.Block{
				Type:  BlockPublicKey,
				Bytes: keyBytes,
			}

			pemBlocks = append(pemBlocks, pemBlock)
		case *dsa.PublicKey:
			var keyBytes []byte
			var pemBlock *pem.Block

			//TODO: Should marshal be the same for both
			if legacy {
				keyBytes, err = MarshalDSAPublicKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal DSA public key: %w", err)
				}

				pemBlock = &pem.Block{
					Type:  BlockDSAPublicKey,
					Bytes: keyBytes,
				}
			} else {
				keyBytes, err = MarshalDSAPublicKey(k)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal DSA public key: %w", err)
				}

				pemBlock = &pem.Block{
					Type:  BlockPublicKey,
					Bytes: keyBytes,
				}
			}

			pemBlocks = append(pemBlocks, pemBlock)
		default:
			return nil, fmt.Errorf("unsupported public key type: %T", publicKey)
		}
	}

	for _, certificate := range certificates {
		var pemBlock *pem.Block

		if encryptCertificate && len(password) > 0 {
			randomReader := rand.Reader
			//nolint:staticcheck // SA1019 we are keeping backwards compatibility with old certificate types
			pemBlock, err = x509.EncryptPEMBlock(randomReader, BlockCertificate, certificate.Raw, []byte(password), x509.PEMCipherAES256)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt PEM block: %w", err)
			}
		} else {
			pemBlock = &pem.Block{
				Type:  BlockCertificate,
				Bytes: certificate.Raw,
			}
		}

		pemBlocks = append(pemBlocks, pemBlock)
	}

	for _, certificateRequest := range certificateRequests {
		pemBlock := &pem.Block{
			Type:  BlockPublicKey,
			Bytes: certificateRequest.Raw,
		}

		pemBlocks = append(pemBlocks, pemBlock)
	}

	var buffer bytes.Buffer

	for _, pemBlock := range pemBlocks {
		if pemBlock != nil {
			// Encode the block and append it to the buffer
			buffer.Write(pem.EncodeToMemory(pemBlock))
		}
	}

	return buffer.Bytes(), nil
}

func ConvertPemToPkcs12(pemData []byte, pemPassword string, pfxPassword string) (pkcs12Data []byte, err error) {
	legacy := false

	privateKeys, _, certificates, _, err := ParsePem(pemData, pemPassword, legacy)
	if err != nil {
		return nil, err
	}

	if len(privateKeys) < 1 {
		return nil, errors.New("no private key found in the PEM data")
	}

	if len(privateKeys) > 1 {
		return nil, errors.New("more then 1 private key found in the PEM data")
	}

	if len(certificates) < 1 {
		return nil, errors.New("no certificate found in the PEM data")
	}

	privateKey := privateKeys[0]
	certificate := certificates[0]
	caCerts := make([]*x509.Certificate, 0)
	if len(certificates) > 1 {
		caCerts = certificates[:1]
	}

	pkcs12Data, err = MarshalPkcs12(privateKey, certificate, caCerts, pfxPassword, legacy)
	if err != nil {
		return nil, err
	}

	return pkcs12Data, nil
}

func ParsePkcs12(pkcs12Data []byte, password string) (privateKey any, certificates *x509.Certificate, caCerts []*x509.Certificate, err error) {
	return pkcs12.DecodeChain(pkcs12Data, password)
}

func MarshalPkcs12(privateKey any, certificate *x509.Certificate, caCerts []*x509.Certificate, password string, legacy bool) (pkcs12Data []byte, err error) {
	// Ensure we have the necessary components
	if privateKey == nil {
		return nil, errors.New("no private key specified")
	}

	if certificate == nil {
		return nil, errors.New("no certificate specified")
	}

	//Encoder type to use for Pkcs12
	encoder := pkcs12.Modern
	if legacy {
		encoder = pkcs12.LegacyRC2
	}

	pkcs12Data, err = encoder.Encode(privateKey, certificate, caCerts, password)
	if err != nil {
		return nil, fmt.Errorf("failed to encode PKCS12 data: %v", err)
	}

	return pkcs12Data, nil
}

func ConvertPkcs12ToPem(pkcs12Data []byte, pkcs12Password string, pemPassword string) (pemData []byte, err error) {
	legacy := false

	privateKey, certificates, _, err := ParsePkcs12(pkcs12Data, pkcs12Password)
	if err != nil {
		return nil, err
	}

	if privateKey == nil {
		return nil, errors.New("no private key found in the pkcs12")
	}

	// Convert certificates to []*x509.Certificate
	certSlice := []*x509.Certificate{certificates}

	if len(certSlice) < 1 {
		return nil, errors.New("no certificate found in the pkcs12")
	}

	pemData, err = MarshalPem([]any{privateKey}, []any{}, certSlice, []*x509.CertificateRequest{}, pemPassword, false, legacy)
	if err != nil {
		return nil, err
	}

	return pemData, nil
}

func MarshalDSAPrivateKey(pk *dsa.PrivateKey) ([]byte, error) {
	type dsaOpenssl struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Pub     *big.Int
		Priv    *big.Int
	}

	k := dsaOpenssl{
		Version: 0,
		P:       pk.P,
		Q:       pk.Q,
		G:       pk.G,
		Pub:     pk.Y,
		Priv:    pk.X,
	}

	return asn1.Marshal(k)
}

func MarshalDSAPublicKey(publicKey *dsa.PublicKey) (keyBytes []byte, err error) {
	//TODO: what sshould this be
	// Encode the private key using ASN.1
	keyBytes, err = asn1.Marshal(publicKey)
	if err != nil {
		return nil, err
	}

	return keyBytes, err
}

// ParseDSAPrivateKey returns a DSA private key from its ASN.1 DER encoding, as
// specified by the OpenSSL DSA man page.
func ParseDSAPrivateKey(der []byte) (*dsa.PrivateKey, error) {
	var k struct {
		Version int
		P       *big.Int
		Q       *big.Int
		G       *big.Int
		Pub     *big.Int
		Priv    *big.Int
	}
	rest, err := asn1.Unmarshal(der, &k)
	if err != nil {
		return nil, errors.New("ssh: failed to parse DSA key: " + err.Error())
	}
	if len(rest) > 0 {
		return nil, errors.New("ssh: garbage after DSA key")
	}
	return &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.P,
				Q: k.Q,
				G: k.G,
			},
			Y: k.Pub,
		},
		X: k.Priv,
	}, nil
}

func base64Decode(body []byte) ([]byte, error) {
	//Base64 Decode
	b64 := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
	n, err := base64.StdEncoding.Decode(b64, body)
	if err != nil {
		return nil, err
	}
	return b64[:n], nil
}
