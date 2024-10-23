// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

// Generalized function to compare private keys
func comparePrivateKeys(t *testing.T, expectedPEM, actualPEM string) {
	// Parse the expected private key
	expectedBlock, _ := pem.Decode([]byte(expectedPEM))
	if expectedBlock == nil {
		t.Fatalf("Failed to decode expected private key PEM")
	}

	expectedKey, err := ParsePrivateKey(expectedBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse expected private key: %v", err)
	}

	// Parse the actual private key
	actualBlock, _ := pem.Decode([]byte(actualPEM))
	if actualBlock == nil {
		t.Fatalf("Failed to decode actual private key PEM")
	}

	actualKey, err := ParsePrivateKey(actualBlock.Bytes)
	if err != nil {
		t.Fatalf("Failed to parse actual private key: %v", err)
	}

	// Compare keys based on their type
	switch expected := expectedKey.(type) {
	case *rsa.PrivateKey:
		actualRSA, ok := actualKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("Expected RSA private key, got a different type")
		}
		assert.Equal(t, expected.N, actualRSA.N, "Modulus (n) mismatch")
		assert.Equal(t, expected.E, actualRSA.E, "Public exponent (e) mismatch")
		assert.Equal(t, expected.D, actualRSA.D, "Private exponent (d) mismatch")

	case *ecdsa.PrivateKey:
		actualECDSA, ok := actualKey.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("Expected ECDSA private key, got a different type")
		}
		assert.Equal(t, expected.D, actualECDSA.D, "ECDSA private key D mismatch")
		assert.Equal(t, expected.X, actualECDSA.X, "ECDSA public key X mismatch")
		assert.Equal(t, expected.Y, actualECDSA.Y, "ECDSA public key Y mismatch")

	case ed25519.PrivateKey:
		actualEd25519, ok := actualKey.(ed25519.PrivateKey)
		if !ok {
			t.Fatalf("Expected ED25519 private key, got a different type")
		}
		assert.Equal(t, expected, actualEd25519, "Ed25519 private key mismatch")

	default:
		t.Fatalf("Unsupported private key type: %T", expectedKey)
	}
}

func TestDataSourcePfxToPem_RSALegacyCertificateContentMatches(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPemContent, err := os.ReadFile("fixtures/certificate_rsa_legacy.pem")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	privateKeyContent, err := os.ReadFile("fixtures/private_key_rsa_legacy.pem")
	if err != nil {
		t.Fatalf("Failed to load private key fixture: %v", err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_pfx_to_pem" "test" {
						content_base64 = filebase64("fixtures/certificate_rsa_legacy.pfx")
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check the count of certificates and private keys
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.#", "1"),
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "private_keys_pem.#", "1"),

					// Check the content of the first certificate in the list
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.0", strings.TrimSpace(string(certPemContent))+"\n"),

					// Verify and compare private key content without relying on headers
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.tls_pfx_to_pem.test"]
						if !ok {
							return assert.AnError
						}

						// Get the actual private key from the resource state
						actualPrivateKey := rs.Primary.Attributes["private_keys_pem.0"]

						// Compare private keys
						comparePrivateKeys(t, string(privateKeyContent), actualPrivateKey)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePfxToPem_RSACertificateContentMatches(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPemContent, err := os.ReadFile("fixtures/certificate_rsa.pem")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	privateKeyContent, err := os.ReadFile("fixtures/private_key_rsa.pem")
	if err != nil {
		t.Fatalf("Failed to load private key fixture: %v", err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_pfx_to_pem" "test" {
						content_base64 = filebase64("fixtures/certificate_rsa.pfx")
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check the count of certificates and private keys
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.#", "1"),
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "private_keys_pem.#", "1"),

					// Check the content of the first certificate in the list
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.0", strings.TrimSpace(string(certPemContent))+"\n"),

					// Verify and compare private key content without relying on headers
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.tls_pfx_to_pem.test"]
						if !ok {
							return assert.AnError
						}

						// Get the actual private key from the resource state
						actualPrivateKey := rs.Primary.Attributes["private_keys_pem.0"]

						// Compare private keys
						comparePrivateKeys(t, string(privateKeyContent), actualPrivateKey)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePfxToPem_RSACertificateChainContentWithNoPasswordMatches(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPemContent, err := os.ReadFile("fixtures/certificate_rsa_chain.pem")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	privateKeyContent, err := os.ReadFile("fixtures/private_key_rsa_chain.pem")
	if err != nil {
		t.Fatalf("Failed to load private key fixture: %v", err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_pfx_to_pem" "test" {
						content_base64 = filebase64("fixtures/certificate_rsa_chain_unencrypted.pfx")
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check the count of certificates and private keys
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.#", "1"),
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "private_keys_pem.#", "1"),

					// Check the content of the first certificate in the list
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.0", strings.TrimSpace(string(certPemContent))+"\n"),

					// Verify and compare private key content without relying on headers
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.tls_pfx_to_pem.test"]
						if !ok {
							return assert.AnError
						}

						// Get the actual private key from the resource state
						actualPrivateKey := rs.Primary.Attributes["private_keys_pem.0"]

						// Compare private keys
						comparePrivateKeys(t, string(privateKeyContent), actualPrivateKey)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePfxToPem_RSACertificateChainContentWithPasswordMatches(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPemContent, err := os.ReadFile("fixtures/certificate_rsa_chain.pem")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	privateKeyContent, err := os.ReadFile("fixtures/private_key_rsa_chain.pem")
	if err != nil {
		t.Fatalf("Failed to load private key fixture: %v", err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_pfx_to_pem" "test" {
						content_base64 = filebase64("fixtures/certificate_rsa_chain_encrypted.pfx")
						password_pfx       = "password"
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check the count of certificates and private keys
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.#", "1"),
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "private_keys_pem.#", "1"),

					// Check the content of the first certificate in the list
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.0", strings.TrimSpace(string(certPemContent))+"\n"),

					// Verify and compare private key content without relying on headers
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.tls_pfx_to_pem.test"]
						if !ok {
							return assert.AnError
						}

						// Get the actual private key from the resource state
						actualPrivateKey := rs.Primary.Attributes["private_keys_pem.0"]

						// Compare private keys
						comparePrivateKeys(t, string(privateKeyContent), actualPrivateKey)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePfxToPem_ED25519CertificateContentMatches(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPemContent, err := os.ReadFile("fixtures/certificate_ed25519.pem")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	privateKeyContent, err := os.ReadFile("fixtures/private_key_ed25519.pem")
	if err != nil {
		t.Fatalf("Failed to load private key fixture: %v", err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_pfx_to_pem" "test" {
						content_base64 = filebase64("fixtures/certificate_ed25519.pfx")
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check the count of certificates and private keys
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.#", "1"),
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "private_keys_pem.#", "1"),

					// Check the content of the first certificate in the list
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.0", strings.TrimSpace(string(certPemContent))+"\n"),

					// Verify and compare private key content without relying on headers
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.tls_pfx_to_pem.test"]
						if !ok {
							return assert.AnError
						}

						// Get the actual private key from the resource state
						actualPrivateKey := rs.Primary.Attributes["private_keys_pem.0"]

						// Compare private keys
						comparePrivateKeys(t, string(privateKeyContent), actualPrivateKey)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePfxToPem_ECDSACertificateContentMatches(t *testing.T) {
	// Load the expected certificate and private key content from fixtures
	certPemContent, err := os.ReadFile("fixtures/certificate_ecdsa.pem")
	if err != nil {
		t.Fatalf("Failed to load certificate fixture: %v", err)
	}

	privateKeyContent, err := os.ReadFile("fixtures/private_key_ecdsa.pem")
	if err != nil {
		t.Fatalf("Failed to load private key fixture: %v", err)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_pfx_to_pem" "test" {
						content_base64 = filebase64("fixtures/certificate_ecdsa.pfx")
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					// Check the count of certificates and private keys
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.#", "1"),
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "private_keys_pem.#", "1"),

					// Check the content of the first certificate in the list
					resource.TestCheckResourceAttr("data.tls_pfx_to_pem.test", "certificates_pem.0", strings.TrimSpace(string(certPemContent))+"\n"),

					// Verify and compare private key content without relying on headers
					func(s *terraform.State) error {
						rs, ok := s.RootModule().Resources["data.tls_pfx_to_pem.test"]
						if !ok {
							return assert.AnError
						}

						// Get the actual private key from the resource state
						actualPrivateKey := rs.Primary.Attributes["private_keys_pem.0"]

						// Compare private keys
						comparePrivateKeys(t, string(privateKeyContent), actualPrivateKey)
						return nil
					},
				),
			},
		},
	})
}
