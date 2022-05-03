package provider

import (
	"fmt"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestPrivateKeyRSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					output "private_key_pem" {
						value = "${tls_private_key.test.private_key_pem}"
						sensitive = true
					}
					output "private_key_openssh" {
						value = "${tls_private_key.test.private_key_openssh}"
						sensitive = true
					}
					output "public_key_pem" {
						value = "${tls_private_key.test.public_key_pem}"
					}
					output "public_key_openssh" {
						value = "${tls_private_key.test.public_key_openssh}"
					}
					output "public_key_fingerprint_md5" {
						value = "${tls_private_key.test.public_key_fingerprint_md5}"
					}
					output "public_key_fingerprint_sha256" {
						value = "${tls_private_key.test.public_key_fingerprint_sha256}"
					}
				`,
				Check: func(s *terraform.State) error {
					// Check `.private_key_pem`
					gotPrivateUntyped := s.RootModule().Outputs["private_key_pem"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPrivate, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key PEM preamble")
					}
					if len(gotPrivate) > 1700 {
						return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(gotPrivate))
					}

					// Check `.public_key_pem`
					gotPublicUntyped := s.RootModule().Outputs["public_key_pem"].Value
					gotPublic, ok := gotPublicUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPublic, "-----BEGIN PUBLIC KEY----") {
						return fmt.Errorf("public key is missing public key PEM preamble")
					}

					// Check `.public_key_openssh`
					gotPublicSSHUntyped := s.RootModule().Outputs["public_key_openssh"].Value
					gotPublicSSH, ok := gotPublicSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPublicSSH, "ssh-rsa ") {
						return fmt.Errorf("SSH public key is missing ssh-rsa prefix")
					}

					// Check `.private_key_openssh`
					gotPrivateSSHUntyped := s.RootModule().Outputs["private_key_openssh"].Value
					gotPrivateSSH, ok := gotPrivateSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPrivateSSH, "-----BEGIN OPENSSH PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key OPENSSH PEM preamble")
					}

					// Check `.public_key_fingerprint_md5`
					gotPublicFingerprintMD5Untyped := s.RootModule().Outputs["public_key_fingerprint_md5"].Value
					gotPublicFingerprintMD5, ok := gotPublicFingerprintMD5Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_md5\" is not a string")
					}
					if gotPublicFingerprintMD5[2] != ':' {
						return fmt.Errorf("MD5 public key fingerprint is missing ':' in the correct place")
					}

					// Check `.public_key_fingerprint_sha256`
					gotPublicFingerprintSHA256Untyped := s.RootModule().Outputs["public_key_fingerprint_sha256"].Value
					gotPublicFingerprintSHA256, ok := gotPublicFingerprintSHA256Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_sha256\" is not a string")
					}
					if !(strings.HasPrefix(gotPublicFingerprintSHA256, "SHA256:")) {
						return fmt.Errorf("SHA256 public key fingerprint is is missing the expected preamble")
					}

					return nil
				},
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
						rsa_bits = 4096
					}
					output "key_pem" {
						value = "${tls_private_key.test.private_key_pem}"
						sensitive = true
					}
				`,
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["key_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem\" is not a string")
					}
					if !strings.HasPrefix(got, "-----BEGIN RSA PRIVATE KEY----") {
						return fmt.Errorf("key is missing RSA key PEM preamble")
					}
					if len(got) < 1700 {
						return fmt.Errorf("key PEM looks too short for a 4096-bit key (got %v characters)", len(got))
					}
					return nil
				},
			},
		},
	})
}

func TestPrivateKeyECDSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
					output "private_key_pem" {
						value = "${tls_private_key.test.private_key_pem}"
						sensitive = true
					}
					output "private_key_openssh" {
						value = "${tls_private_key.test.private_key_openssh}"
						sensitive = true
					}
					output "public_key_pem" {
						value = "${tls_private_key.test.public_key_pem}"
					}
					output "public_key_openssh" {
						value = "${tls_private_key.test.public_key_openssh}"
					}
					output "public_key_fingerprint_md5" {
						value = "${tls_private_key.test.public_key_fingerprint_md5}"
					}
					output "public_key_fingerprint_sha256" {
						value = "${tls_private_key.test.public_key_fingerprint_sha256}"
					}
				`,
				Check: func(s *terraform.State) error {
					// Check `.private_key_pem`
					gotPrivateUntyped := s.RootModule().Outputs["private_key_pem"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPrivate, "-----BEGIN EC PRIVATE KEY----") {
						return fmt.Errorf("private key is missing EC key PEM preamble")
					}

					// Check `.public_key_pem`
					gotPublicUntyped := s.RootModule().Outputs["public_key_pem"].Value
					gotPublic, ok := gotPublicUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPublic, "-----BEGIN PUBLIC KEY----") {
						return fmt.Errorf("public key is missing public key PEM preamble")
					}

					// Check `.public_key_openssh`
					gotPublicSSHUntyped := s.RootModule().Outputs["public_key_openssh"].Value
					gotPublicSSH, ok := gotPublicSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_openssh\" is not a string")
					}
					if gotPublicSSH != "" {
						return fmt.Errorf("SSH public key should not be set for ECDSA P-224 key")
					}

					// Check `.private_key_openssh`
					gotPrivateSSHUntyped := s.RootModule().Outputs["private_key_openssh"].Value
					gotPrivateSSH, ok := gotPrivateSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_openssh\" is not a string")
					}
					if gotPrivateSSH != "" {
						return fmt.Errorf("SSH private key should not be set for ECDSA P-224 key")
					}

					// Check `.public_key_fingerprint_md5`
					gotPublicFingerprintMD5Untyped := s.RootModule().Outputs["public_key_fingerprint_md5"].Value
					gotPublicFingerprintMD5, ok := gotPublicFingerprintMD5Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_md5\" is not a string")
					}
					if gotPublicFingerprintMD5 != "" {
						return fmt.Errorf("MD5 public key fingerprint should not be set for ECDSA P-224 key")
					}

					// Check `.public_key_fingerprint_sha256`
					gotPublicFingerprintSHA256Untyped := s.RootModule().Outputs["public_key_fingerprint_sha256"].Value
					gotPublicFingerprintSHA256, ok := gotPublicFingerprintSHA256Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_sha256\" is not a string")
					}
					if gotPublicFingerprintSHA256 != "" {
						return fmt.Errorf("SHA256 public key fingerprint should not be st for ECDSA P-224 key")
					}

					return nil
				},
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
					output "private_key_pem" {
						value = "${tls_private_key.test.private_key_pem}"
						sensitive = true
					}
					output "private_key_openssh" {
						value = "${tls_private_key.test.private_key_openssh}"
						sensitive = true
					}
					output "public_key_pem" {
						value = "${tls_private_key.test.public_key_pem}"
					}
					output "public_key_openssh" {
						value = "${tls_private_key.test.public_key_openssh}"
					}
					output "public_key_fingerprint_md5" {
						value = "${tls_private_key.test.public_key_fingerprint_md5}"
					}
					output "public_key_fingerprint_sha256" {
						value = "${tls_private_key.test.public_key_fingerprint_sha256}"
					}
				`,
				Check: func(s *terraform.State) error {
					// Check `.private_key_pem`
					gotPrivateUntyped := s.RootModule().Outputs["private_key_pem"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPrivate, "-----BEGIN EC PRIVATE KEY----") {
						return fmt.Errorf("private key is missing EC key PEM preamble")
					}

					// Check `.public_key_pem`
					gotPublicUntyped := s.RootModule().Outputs["public_key_pem"].Value
					gotPublic, ok := gotPublicUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPublic, "-----BEGIN PUBLIC KEY----") {
						return fmt.Errorf("public key is missing public key PEM preamble")
					}

					// Check `.public_key_openssh`
					gotPublicSSHUntyped := s.RootModule().Outputs["public_key_openssh"].Value
					gotPublicSSH, ok := gotPublicSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPublicSSH, "ecdsa-sha2-nistp256 ") {
						return fmt.Errorf("SSH public key is missing ecdsa-sha2-nistp256 prefix")
					}

					// Check `.private_key_openssh`
					gotPrivateSSHUntyped := s.RootModule().Outputs["private_key_openssh"].Value
					gotPrivateSSH, ok := gotPrivateSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPrivateSSH, "-----BEGIN OPENSSH PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key OPENSSH PEM preamble")
					}

					// Check `.public_key_fingerprint_md5`
					gotPublicFingerprintMD5Untyped := s.RootModule().Outputs["public_key_fingerprint_md5"].Value
					gotPublicFingerprintMD5, ok := gotPublicFingerprintMD5Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_md5\" is not a string")
					}
					if gotPublicFingerprintMD5[2] != ':' {
						return fmt.Errorf("MD5 public key fingerprint is missing ':' in the correct place")
					}

					// Check `.public_key_fingerprint_sha256`
					gotPublicFingerprintSHA256Untyped := s.RootModule().Outputs["public_key_fingerprint_sha256"].Value
					gotPublicFingerprintSHA256, ok := gotPublicFingerprintSHA256Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_sha256\" is not a string")
					}
					if !(strings.HasPrefix(gotPublicFingerprintSHA256, "SHA256:")) {
						return fmt.Errorf("SHA256 public key fingerprint is is missing the expected preamble")
					}

					return nil
				},
			},
		},
	})
}

func TestPrivateKeyED25519(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					output "private_key_pem" {
						value = "${tls_private_key.test.private_key_pem}"
						sensitive = true
					}
					output "private_key_openssh" {
						value = "${tls_private_key.test.private_key_openssh}"
						sensitive = true
					}
					output "public_key_pem" {
						value = "${tls_private_key.test.public_key_pem}"
					}
					output "public_key_openssh" {
						value = "${tls_private_key.test.public_key_openssh}"
					}
					output "public_key_fingerprint_md5" {
						value = "${tls_private_key.test.public_key_fingerprint_md5}"
					}
					output "public_key_fingerprint_sha256" {
						value = "${tls_private_key.test.public_key_fingerprint_sha256}"
					}
				`,
				Check: func(s *terraform.State) error {
					// Check `.private_key_pem`
					gotPrivateUntyped := s.RootModule().Outputs["private_key_pem"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPrivate, "-----BEGIN PRIVATE KEY----") {
						return fmt.Errorf("private key is missing ED25519 key PEM preamble")
					}

					// Check `.public_key_pem`
					gotPublicUntyped := s.RootModule().Outputs["public_key_pem"].Value
					gotPublic, ok := gotPublicUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPublic, "-----BEGIN PUBLIC KEY----") {
						return fmt.Errorf("public key is missing public key PEM preamble")
					}

					// Check `.public_key_openssh`
					gotPublicSSHUntyped := s.RootModule().Outputs["public_key_openssh"].Value
					gotPublicSSH, ok := gotPublicSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPublicSSH, "ssh-ed25519 ") {
						return fmt.Errorf("SSH public key is missing sh-ed25519 prefix")
					}

					// Check `.private_key_openssh`
					gotPrivateSSHUntyped := s.RootModule().Outputs["private_key_openssh"].Value
					gotPrivateSSH, ok := gotPrivateSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPrivateSSH, "-----BEGIN OPENSSH PRIVATE KEY----") {
						return fmt.Errorf("private key is missing RSA key OPENSSH PEM preamble")
					}

					// Check `.public_key_fingerprint_md5`
					gotPublicFingerprintMD5Untyped := s.RootModule().Outputs["public_key_fingerprint_md5"].Value
					gotPublicFingerprintMD5, ok := gotPublicFingerprintMD5Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_md5\" is not a string")
					}
					if gotPublicFingerprintMD5[2] != ':' {
						return fmt.Errorf("MD5 public key fingerprint is missing ':' in the correct place")
					}

					// Check `.public_key_fingerprint_sha256`
					gotPublicFingerprintSHA256Untyped := s.RootModule().Outputs["public_key_fingerprint_sha256"].Value
					gotPublicFingerprintSHA256, ok := gotPublicFingerprintSHA256Untyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_sha256\" is not a string")
					}
					if !(strings.HasPrefix(gotPublicFingerprintSHA256, "SHA256:")) {
						return fmt.Errorf("SHA256 public key fingerprint is is missing the expected preamble")
					}

					return nil
				},
			},
		},
	})
}
