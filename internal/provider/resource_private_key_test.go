package provider

import (
	"fmt"
	"regexp"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_pem", regexp.MustCompile(`^-----BEGIN RSA PRIVATE KEY----(.|\s)+-----END RSA PRIVATE KEY-----\n$`)),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_pem", regexp.MustCompile(`^-----BEGIN PUBLIC KEY----(.|\s)+-----END PUBLIC KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_openssh", regexp.MustCompile(`^-----BEGIN OPENSSH PRIVATE KEY----(.|\s)+-----END OPENSSH PRIVATE KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
						rsa_bits = 4096
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_pem", regexp.MustCompile(`^-----BEGIN RSA PRIVATE KEY----(.|\s)+-----END RSA PRIVATE KEY-----\n$`)),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) < 1700 {
							return fmt.Errorf("private key PEM looks too short for a 4096-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
				),
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
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_pem", regexp.MustCompile(`^-----BEGIN EC PRIVATE KEY----(.|\s)+-----END EC PRIVATE KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_pem", regexp.MustCompile(`^-----BEGIN PUBLIC KEY----(.|\s)+-----END PUBLIC KEY-----\n$`)),
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", ""),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_pem", regexp.MustCompile(`^-----BEGIN EC PRIVATE KEY----(.|\s)+-----END EC PRIVATE KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_pem", regexp.MustCompile(`^-----BEGIN PUBLIC KEY----(.|\s)+-----END PUBLIC KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_openssh", regexp.MustCompile(`^-----BEGIN OPENSSH PRIVATE KEY----(.|\s)+-----END OPENSSH PRIVATE KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ecdsa-sha2-nistp256 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
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
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_pem", regexp.MustCompile(`^-----BEGIN PRIVATE KEY----(.|\s)+-----END PRIVATE KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_pem", regexp.MustCompile(`^-----BEGIN PUBLIC KEY----(.|\s)+-----END PUBLIC KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "private_key_openssh", regexp.MustCompile(`^-----BEGIN OPENSSH PRIVATE KEY----(.|\s)+-----END OPENSSH PRIVATE KEY-----\n$`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
		},
	})
}
