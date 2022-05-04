package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

const (
	configDataSourcePublicKeyViaPEM = `
data "tls_public_key" "test" {
	private_key_pem = <<EOF
	%s
	EOF
}
`
	configDataSourcePublicKeyViaOpenSSHPEM = `
data "tls_public_key" "test" {
	private_key_openssh = <<EOF
	%s
	EOF
}
`
)

func TestAccPublicKey_dataSource_PEM(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(configDataSourcePublicKeyViaPEM, testPrivateKeyPEM),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_pem", strings.TrimSpace(testPublicKeyPEM)+"\n"),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_openssh", strings.TrimSpace(testPublicKeyOpenSSH)+"\n"),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_fingerprint_md5", strings.TrimSpace(testPublicKeyOpenSSHFingerprintMD5)),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_fingerprint_x509_sha256", strings.TrimSpace((testPublicKeyX509FingerprintSHA256))),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "algorithm", "RSA"),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					data "tls_public_key" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
					}
				`,
				Check: resource.TestCheckResourceAttrPair(
					"data.tls_public_key.test", "public_key_pem",
					"tls_private_key.test", "public_key_pem",
				),
			},
			{
				Config: `
					resource "tls_private_key" "ecdsaPrvKey" {
						algorithm   = "ECDSA"
						ecdsa_curve = "P384"
					}
					data "tls_public_key" "ecdsaPubKey" {
						private_key_pem = tls_private_key.ecdsaPrvKey.private_key_pem
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.tls_public_key.ecdsaPubKey", "public_key_pem",
						"tls_private_key.ecdsaPrvKey", "public_key_pem",
					),
					resource.TestCheckResourceAttr("data.tls_public_key.ecdsaPubKey", "algorithm", "ECDSA"),
				),
			},
			{
				Config:      fmt.Sprintf(configDataSourcePublicKeyViaPEM, "corrupt"),
				ExpectError: regexp.MustCompile(`failed to decode PEM block: decoded bytes \d, undecoded \d`),
			},
		},
	})
}

func TestAccPublicKey_dataSource_OpenSSHPEM(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(configDataSourcePublicKeyViaOpenSSHPEM, testPrivateKeyOpenSSHPEM),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_pem", strings.TrimSpace(testPublicKeyPEM)+"\n"),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_openssh", strings.TrimSpace(testPublicKeyOpenSSH)+"\n"),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_fingerprint_md5", strings.TrimSpace(testPublicKeyOpenSSHFingerprintMD5)),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_fingerprint_x509_sha256", strings.TrimSpace(testPublicKeyX509FingerprintSHA256)),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "algorithm", "RSA"),
				),
			},
			{
				Config: `
					resource "tls_private_key" "rsaPrvKey" {
						algorithm = "RSA"
					}
					data "tls_public_key" "rsaPubKey" {
						private_key_openssh = tls_private_key.rsaPrvKey.private_key_openssh
					}
				`,
				Check: resource.TestCheckResourceAttrPair(
					"data.tls_public_key.rsaPubKey", "public_key_openssh",
					"tls_private_key.rsaPrvKey", "public_key_openssh",
				),
			},
			{
				Config: `
					resource "tls_private_key" "ed25519PrvKey" {
						algorithm   = "ED25519"
					}
					data "tls_public_key" "ed25519PubKey" {
						private_key_openssh = tls_private_key.ed25519PrvKey.private_key_openssh
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrPair(
						"data.tls_public_key.ed25519PubKey", "public_key_openssh",
						"tls_private_key.ed25519PrvKey", "public_key_openssh",
					),
					resource.TestCheckResourceAttr("data.tls_public_key.ed25519PubKey", "algorithm", "ED25519"),
				),
			},
			{
				Config:      fmt.Sprintf(configDataSourcePublicKeyViaOpenSSHPEM, "corrupt"),
				ExpectError: regexp.MustCompile("ssh: no key found"),
			},
		},
	})
}

func TestAccPublicKey_dataSource_errorCases(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProviderFactories: testProviders,
		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_public_key" "test" {
						private_key_pem = "does not matter"
						private_key_openssh = "does not matter"
					}
				`,
				ExpectError: regexp.MustCompile("Invalid combination of arguments"),
			},
			{
				Config: `
					data "tls_public_key" "test" {
					}
				`,
				ExpectError: regexp.MustCompile("Invalid combination of arguments"),
			},
		},
	})
}
