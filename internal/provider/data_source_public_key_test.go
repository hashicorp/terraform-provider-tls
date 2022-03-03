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

func TestAccPublicKey_dataSource(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		Providers: testProviders,
		Steps: []resource.TestStep{
			{
				Config: fmt.Sprintf(configDataSourcePublicKeyViaPEM, testPrivateKeyPEM),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_pem", strings.TrimSpace(expectedPublic)+"\n"),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_openssh", strings.TrimSpace(expectedPublicSSH)+"\n"),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_fingerprint_md5", strings.TrimSpace(expectedPublicFingerprintMD5)),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					data "tls_public_key" "test" {
						private_key_pem = "${tls_private_key.test.private_key_pem}"
					}
				`,
				Check: resource.TestCheckResourceAttrPair(
					"data.tls_public_key.test", "public_key_pem",
					"tls_private_key.test", "public_key_pem"),
			},
			{
				Config: `
					resource "tls_private_key" "key" {
						algorithm   = "ECDSA"
						ecdsa_curve = "P384"
					}
					data "tls_public_key" "pub" {
						private_key_pem = "${tls_private_key.key.private_key_pem}"
					}
				`,
				Check: resource.TestCheckResourceAttrPair(
					"data.tls_public_key.pub", "public_key_pem",
					"tls_private_key.key", "public_key_pem"),
			},
			{
				Config:      fmt.Sprintf(testAccDataSourcePublicKeyConfig, "corrupt"),
				ExpectError: regexp.MustCompile("failed to decode PEM block containing private key of type \"unknown\""),
			},
		},
	})
}

}
