// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	// For Terraform state access
)

func ComparePFXCertificateProperties(t *testing.T, generatedPfxPath string, expectedPfxPath string, expectedPfxPassword string) error {

	// Extract properties from the expected PFX file
	expectedProperties, err := ExtractPFXProperties(expectedPfxPath, expectedPfxPassword)
	if err != nil {
		t.Fatalf("Failed to extract properties from expected PFX file: %v", err)
	}

	// Extract properties from the generated PFX file
	generatedProperties, err := ExtractPFXProperties(generatedPfxPath, expectedPfxPassword)
	if err != nil {
		t.Fatalf("Failed to extract properties from generated PFX file: %v", err)
	}

	// Compare properties
	for key, expectedValue := range expectedProperties {
		if generatedValue, ok := generatedProperties[key]; !ok || generatedValue != expectedValue {
			t.Errorf("Mismatch in property %q: expected %v, got %v", key, expectedValue, generatedValue)
		}
	}
	return nil
}

// Extracts key properties from a PFX file.
func ExtractPFXProperties(pfxPath string, password string) (map[string]interface{}, error) {
	// Read the PFX file
	pfxData, err := os.ReadFile(pfxPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PFX file: %v", err)
	}

	// Decode the PFX
	privateKey, cert, _, err := ParsePkcs12([]byte(pfxData), password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PFX file: %v", err)
	}

	// Extract properties from the certificate
	properties := map[string]interface{}{
		"Subject":      cert.Subject.String(),
		"Issuer":       cert.Issuer.String(),
		"NotBefore":    cert.NotBefore,
		"NotAfter":     cert.NotAfter,
		"SerialNumber": cert.SerialNumber.String(),
		"PublicKey":    fmt.Sprintf("%v", cert.PublicKey),
	}

	// Include private key details
	if privateKey != nil {
		// Add the private key type
		properties["PrivateKeyType"] = fmt.Sprintf("%T", privateKey)

		// Marshal private key to PEM format and include its content
		privateKeyPEMBlock, err := MarshalPrivateKeyToPEM(privateKey, true)
		if err != nil {
			return nil, fmt.Errorf("failed to encode private key to PEM: %v", err)
		}

		// Convert to PEM format
		pemBytes := pem.EncodeToMemory(privateKeyPEMBlock)
		properties["PrivateKeyContent"] = string(pemBytes)
	}

	return properties, nil
}

func TestDataSourcePemToPfx_RSALegacyCertificateContentMatches(t *testing.T) {

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pem_to_pfx" "test" {
						certificate_pem = file("fixtures/certificate_rsa_legacy.pem")
						private_key_pem = file("fixtures/private_key_rsa_legacy.pem")
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Generate PFX and save it to a file
					func(s *terraform.State) error {
						// Access the resource data
						resource := s.RootModule().Resources["data.tls_pem_to_pfx.test"]
						if resource == nil {
							return fmt.Errorf("resource not found")
						}

						// Get the certificate_pfx value
						certificatePfxBase64 := resource.Primary.Attributes["certificate_pfx"]

						// Decode the Base64 data
						certificatePfxBytes, err := base64.StdEncoding.DecodeString(certificatePfxBase64)
						if err != nil {
							return fmt.Errorf("failed to decode Base64 certificate_pfx: %v", err)
						}

						// Save the PFX binary data to a file
						outputPfxPath := "fixtures/generated_certificate_rsa_legacy.pfx"
						err = os.WriteFile(outputPfxPath, certificatePfxBytes, 0644)
						if err != nil {
							return fmt.Errorf("failed to write PFX file: %v", err)
						}

						expectedPfxPath := "fixtures/certificate_rsa_legacy.pfx"
						expectedPfxPassword := resource.Primary.Attributes["password_pfx"]
						ComparePFXCertificateProperties(t, outputPfxPath, expectedPfxPath, expectedPfxPassword)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePemToPfx_RSACertificateContentMatches(t *testing.T) {

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pem_to_pfx" "test" {
						password_pfx    = ""
						certificate_pem = file("fixtures/certificate_rsa.pem")
						private_key_pem = file("fixtures/private_key_rsa.pem")
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Generate PFX and save it to a file
					func(s *terraform.State) error {
						// Access the resource data
						resource := s.RootModule().Resources["data.tls_pem_to_pfx.test"]
						if resource == nil {
							return fmt.Errorf("resource not found")
						}

						// Get the certificate_pfx value
						certificatePfxBase64 := resource.Primary.Attributes["certificate_pfx"]

						// Decode the Base64 data
						certificatePfxBytes, err := base64.StdEncoding.DecodeString(certificatePfxBase64)
						if err != nil {
							return fmt.Errorf("failed to decode Base64 certificate_pfx: %v", err)
						}

						// Save the PFX binary data to a file
						outputPfxPath := "fixtures/generated_certificate_rsa.pfx"
						err = os.WriteFile(outputPfxPath, certificatePfxBytes, 0644)
						if err != nil {
							return fmt.Errorf("failed to write PFX file: %v", err)
						}

						expectedPfxPath := "fixtures/certificate_rsa.pfx"
						expectedPfxPassword := resource.Primary.Attributes["password_pfx"]
						ComparePFXCertificateProperties(t, outputPfxPath, expectedPfxPath, expectedPfxPassword)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePemToPfx_RSACertificateChainContentWithPasswordMatches(t *testing.T) {

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pem_to_pfx" "test" {
						password_pfx    = "password"
						password_pem    = ""
						certificate_pem = file("fixtures/certificate_rsa_chain.pem")
						private_key_pem = file("fixtures/private_key_rsa_chain.pem")
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Generate PFX and save it to a file
					func(s *terraform.State) error {
						// Access the resource data
						resource := s.RootModule().Resources["data.tls_pem_to_pfx.test"]
						if resource == nil {
							return fmt.Errorf("resource not found")
						}

						// Get the certificate_pfx value
						certificatePfxBase64 := resource.Primary.Attributes["certificate_pfx"]

						// Decode the Base64 data
						certificatePfxBytes, err := base64.StdEncoding.DecodeString(certificatePfxBase64)
						if err != nil {
							return fmt.Errorf("failed to decode Base64 certificate_pfx: %v", err)
						}

						// Save the PFX binary data to a file
						outputPfxPath := "fixtures/generated_certificate_rsa_chain_encrypted.pfx"
						err = os.WriteFile(outputPfxPath, certificatePfxBytes, 0644)
						if err != nil {
							return fmt.Errorf("failed to write PFX file: %v", err)
						}

						expectedPfxPath := "fixtures/certificate_rsa_chain_encrypted.pfx"
						expectedPfxPassword := resource.Primary.Attributes["password_pfx"]
						ComparePFXCertificateProperties(t, outputPfxPath, expectedPfxPath, expectedPfxPassword)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePemToPfx_RSACertificateChainContentWithNoPasswordMatches(t *testing.T) {

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pem_to_pfx" "test" {
						certificate_pem = file("fixtures/certificate_rsa_chain.pem")
						private_key_pem = file("fixtures/private_key_rsa_chain.pem")
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Generate PFX and save it to a file
					func(s *terraform.State) error {
						// Access the resource data
						resource := s.RootModule().Resources["data.tls_pem_to_pfx.test"]
						if resource == nil {
							return fmt.Errorf("resource not found")
						}

						// Get the certificate_pfx value
						certificatePfxBase64 := resource.Primary.Attributes["certificate_pfx"]

						// Decode the Base64 data
						certificatePfxBytes, err := base64.StdEncoding.DecodeString(certificatePfxBase64)
						if err != nil {
							return fmt.Errorf("failed to decode Base64 certificate_pfx: %v", err)
						}

						// Save the PFX binary data to a file
						outputPfxPath := "fixtures/generated_certificate_rsa_chain_unencrypted.pfx"
						err = os.WriteFile(outputPfxPath, certificatePfxBytes, 0644)
						if err != nil {
							return fmt.Errorf("failed to write PFX file: %v", err)
						}

						expectedPfxPath := "fixtures/certificate_rsa_chain_unencrypted.pfx"
						expectedPfxPassword := resource.Primary.Attributes["password_pfx"]
						ComparePFXCertificateProperties(t, outputPfxPath, expectedPfxPath, expectedPfxPassword)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePemToPfx_ED25519CertificateContentMatches(t *testing.T) {

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pem_to_pfx" "test" {
						certificate_pem = file("fixtures/certificate_ed25519.pem")
						private_key_pem = file("fixtures/private_key_ed25519.pem")
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Generate PFX and save it to a file
					func(s *terraform.State) error {
						// Access the resource data
						resource := s.RootModule().Resources["data.tls_pem_to_pfx.test"]
						if resource == nil {
							return fmt.Errorf("resource not found")
						}

						// Get the certificate_pfx value
						certificatePfxBase64 := resource.Primary.Attributes["certificate_pfx"]

						// Decode the Base64 data
						certificatePfxBytes, err := base64.StdEncoding.DecodeString(certificatePfxBase64)
						if err != nil {
							return fmt.Errorf("failed to decode Base64 certificate_pfx: %v", err)
						}

						// Save the PFX binary data to a file
						outputPfxPath := "fixtures/generated_certificate_ed25519.pfx"
						err = os.WriteFile(outputPfxPath, certificatePfxBytes, 0644)
						if err != nil {
							return fmt.Errorf("failed to write PFX file: %v", err)
						}

						expectedPfxPath := "fixtures/certificate_ed25519.pfx"
						expectedPfxPassword := resource.Primary.Attributes["password_pfx"]
						ComparePFXCertificateProperties(t, outputPfxPath, expectedPfxPath, expectedPfxPassword)
						return nil
					},
				),
			},
		},
	})
}

func TestDataSourcePemToPfx_ECDSACertificateContentMatches(t *testing.T) {

	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),

		Steps: []r.TestStep{
			{
				Config: `
					data "tls_pem_to_pfx" "test" {
						certificate_pem = file("fixtures/certificate_ecdsa.pem")
						private_key_pem = file("fixtures/private_key_ecdsa.pem")
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					// Generate PFX and save it to a file
					func(s *terraform.State) error {
						// Access the resource data
						resource := s.RootModule().Resources["data.tls_pem_to_pfx.test"]
						if resource == nil {
							return fmt.Errorf("resource not found")
						}

						// Get the certificate_pfx value
						certificatePfxBase64 := resource.Primary.Attributes["certificate_pfx"]

						// Decode the Base64 data
						certificatePfxBytes, err := base64.StdEncoding.DecodeString(certificatePfxBase64)
						if err != nil {
							return fmt.Errorf("failed to decode Base64 certificate_pfx: %v", err)
						}

						// Save the PFX binary data to a file
						outputPfxPath := "fixtures/generated_certificate_ecdsa.pfx"
						err = os.WriteFile(outputPfxPath, certificatePfxBytes, 0644)
						if err != nil {
							return fmt.Errorf("failed to write PFX file: %v", err)
						}

						expectedPfxPath := "fixtures/certificate_ecdsa.pfx"
						expectedPfxPassword := resource.Primary.Attributes["password_pfx"]
						ComparePFXCertificateProperties(t, outputPfxPath, expectedPfxPath, expectedPfxPassword)
						return nil
					},
				),
			},
		},
	})
}
