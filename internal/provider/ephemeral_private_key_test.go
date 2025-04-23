// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	tu "github.com/hashicorp/terraform-provider-tls/internal/provider/testutils"
)

func TestAccEphemeralPrivateKey_RSA_DefaultRsaBits(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []r.TestStep{
			{
				Config: addEchoConfig(`
					ephemeral "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`),
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("echo.tls_private_key_test", "data.private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.rsa_bits", "2048"),
				),
			},
		},
	})
}

func TestAccEphemeralPrivateKey_RSA_4096RsaBits(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []r.TestStep{
			{
				Config: addEchoConfig(`ephemeral "tls_private_key" "test" {
						algorithm = "RSA"
						rsa_bits = 4096
					}`),
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("echo.tls_private_key_test", "data.private_key_pem", func(pem string) error {
						if len(pem) < 1700 {
							return fmt.Errorf("private key PEM looks too short for a 4096-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.rsa_bits", "4096"),
				),
			},
		},
	})
}

func TestAccEphemeralPrivateKey_ECDSA_DefaultEcdsaCurve(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []r.TestStep{
			{
				Config: addEchoConfig(`ephemeral "tls_private_key" "test" {
						algorithm = "ECDSA"
					}`),
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.private_key_openssh", ""),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.public_key_openssh", ""),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_sha256", ""),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.ecdsa_curve", "P224"),
				),
			},
		},
	})
}

func TestAccEphemeralPrivateKey_ECDSA_P256(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []r.TestStep{
			{
				Config: addEchoConfig(`ephemeral "tls_private_key" "test" {
						algorithm   = "ECDSA"
						ecdsa_curve = "P256"
					}`),
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_openssh", regexp.MustCompile(`^ecdsa-sha2-nistp256 `)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
					r.TestCheckResourceAttr("echo.tls_private_key_test", "data.ecdsa_curve", "P256"),
				),
			},
		},
	})
}

func TestAccEphemeralPrivateKey_ED25519(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		// Ephemeral resources are only available in 1.10 and later
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_10_0),
		},
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
			"echo": echoprovider.NewProviderServer(),
		},
		Steps: []r.TestStep{
			{
				Config: addEchoConfig(`ephemeral "tls_private_key" "test" {
						algorithm = "ED25519"
					}`),
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("echo.tls_private_key_test", "data.private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("echo.tls_private_key_test", "data.public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
		},
	})
}

// Adds the test echo provider to enable using state checks with ephemeral resources.
func addEchoConfig(cfg string) string {
	return fmt.Sprintf(`
	%s
	provider "echo" {
		data = ephemeral.tls_private_key.test
	}
	resource "echo" "tls_private_key_test" {}
	`, cfg)
}
