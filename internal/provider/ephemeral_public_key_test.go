// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/echoprovider"
	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/fixtures"
)

const (
	configEphemeralPublicKeyViaPEM = `
ephemeral "tls_public_key" "test" {
	private_key_pem = <<EOF
	%s
	EOF
}
`
	configEphemeralPublicKeyViaOpenSSHPEM = `
ephemeral "tls_public_key" "test" {
	private_key_openssh = <<EOF
	%s
	EOF
}
`
)

func TestPublicKey_ephemeral_PEM(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "literal RSA PEM",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(fmt.Sprintf(configEphemeralPublicKeyViaPEM, fixtures.TestPrivateKeyPEM)),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_pem", strings.TrimSpace(fixtures.TestPublicKeyPEM)+"\n"),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_openssh", strings.TrimSpace(fixtures.TestPublicKeyOpenSSH)+"\n"),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_fingerprint_md5", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintMD5)),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_fingerprint_sha256", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintSHA256)),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.algorithm", "RSA"),
				),
			},
		},
		{
			desc: "RSA PEM from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					ephemeral "tls_public_key" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
					}
				`),
				Check: r.TestCheckResourceAttrPair(
					"echo.tls_public_key_test", "data.public_key_pem",
					"tls_private_key.test", "public_key_pem",
				),
			},
		},
		{
			desc: "ECDSA PEM from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "ecdsaPrvKey" {
						algorithm   = "ECDSA"
						ecdsa_curve = "P384"
					}
					ephemeral "tls_public_key" "test" {
						private_key_pem = tls_private_key.ecdsaPrvKey.private_key_pem
					}
				`),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttrPair(
						"echo.tls_public_key_test", "data.public_key_pem",
						"tls_private_key.ecdsaPrvKey", "public_key_pem",
					),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.algorithm", "ECDSA"),
				),
			},
		},
		{
			desc: "corrupt PEM",
			step: r.TestStep{
				Config:      ephemeralPublicKeyWithEchoConfig(fmt.Sprintf(configEphemeralPublicKeyViaPEM, "corrupt")),
				ExpectError: regexp.MustCompile(`failed to decode PEM block: decoded bytes \d, undecoded \d`),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_10_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"echo": echoprovider.NewProviderServer(),
				},
				Steps: []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_ephemeral_OpenSSHPEM(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "literal RSA OpenSSH PEM",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(fmt.Sprintf(configEphemeralPublicKeyViaOpenSSHPEM, fixtures.TestPrivateKeyOpenSSHPEM)),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_pem", strings.TrimSpace(fixtures.TestPublicKeyPEM)+"\n"),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_openssh", strings.TrimSpace(fixtures.TestPublicKeyOpenSSH)+"\n"),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_fingerprint_md5", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintMD5)),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.public_key_fingerprint_sha256", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintSHA256)),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.algorithm", "RSA"),
				),
			},
		},
		{
			desc: "RSA OpenSSH PEM from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "rsaPrvKey" {
						algorithm = "RSA"
					}
					ephemeral "tls_public_key" "test" {
						private_key_openssh = tls_private_key.rsaPrvKey.private_key_openssh
					}
				`),
				Check: r.TestCheckResourceAttrPair(
					"echo.tls_public_key_test", "data.public_key_openssh",
					"tls_private_key.rsaPrvKey", "public_key_openssh",
				),
			},
		},
		{
			desc: "ED25519 OpenSSH PEM from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "ed25519PrvKey" {
						algorithm   = "ED25519"
					}
					ephemeral "tls_public_key" "test" {
						private_key_openssh = tls_private_key.ed25519PrvKey.private_key_openssh
					}
				`),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttrPair(
						"echo.tls_public_key_test", "data.public_key_openssh",
						"tls_private_key.ed25519PrvKey", "public_key_openssh",
					),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.algorithm", "ED25519"),
				),
			},
		},
		{
			desc: "corrupt OpenSSH PEM",
			step: r.TestStep{
				Config:      fmt.Sprintf(configEphemeralPublicKeyViaOpenSSHPEM, "corrupt"),
				ExpectError: regexp.MustCompile("ssh: no key found"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				// Ephemeral resources are only available in 1.10 and later
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_10_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"echo": echoprovider.NewProviderServer(),
				},
				Steps: []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_ephemeral_PKCS8PEM(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "RSA PKCS8 PEM from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "rsaPrvKey" {
						algorithm = "RSA"
					}
					ephemeral "tls_public_key" "test" {
						private_key_pem = tls_private_key.rsaPrvKey.private_key_pem_pkcs8
					}
				`),
				Check: r.TestCheckResourceAttrPair(
					"echo.tls_public_key_test", "data.public_key_openssh",
					"tls_private_key.rsaPrvKey", "public_key_openssh",
				),
			},
		},
		{
			desc: "ED25519 PKCS8 PEM from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "ed25519PrvKey" {
						algorithm   = "ED25519"
					}
					ephemeral "tls_public_key" "test" {
						private_key_pem = tls_private_key.ed25519PrvKey.private_key_pem_pkcs8
					}
				`),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttrPair(
						"echo.tls_public_key_test", "data.public_key_openssh",
						"tls_private_key.ed25519PrvKey", "public_key_openssh",
					),
					r.TestCheckResourceAttr("echo.tls_public_key_test", "data.algorithm", "ED25519"),
				),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				// Ephemeral resources are only available in 1.10 and later
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_10_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"echo": echoprovider.NewProviderServer(),
				},
				Steps: []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_ephemeral_OpenSSHComment(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "RSA OpenSSH from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "rsaPrvKey" {
						algorithm = "RSA"
						openssh_comment = "test@test"
					}
					ephemeral "tls_public_key" "test" {
						private_key_openssh = tls_private_key.rsaPrvKey.private_key_openssh
					}
				`),
				Check: r.TestMatchResourceAttr("echo.tls_public_key_test", "data.public_key_openssh", regexp.MustCompile(` test@test\n$`)),
			},
		},
		{
			desc: "ECDSA9 OpenSSH from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "ecdsaPrvKey" {
						algorithm = "ED25519"
						ecdsa_curve = "P384"
						openssh_comment = "test@test"
					}
					ephemeral "tls_public_key" "test" {
						private_key_openssh = tls_private_key.ecdsaPrvKey.private_key_openssh
					}
				`),
				Check: r.TestMatchResourceAttr("echo.tls_public_key_test", "data.public_key_openssh", regexp.MustCompile(` test@test\n$`)),
			},
		},
		{
			desc: "ED25519 OpenSSH from resource",
			step: r.TestStep{
				Config: ephemeralPublicKeyWithEchoConfig(`
					resource "tls_private_key" "ed25519PrvKey" {
						algorithm = "ED25519"
						openssh_comment = "test@test"
					}
					ephemeral "tls_public_key" "test" {
						private_key_openssh = tls_private_key.ed25519PrvKey.private_key_openssh
					}
				`),
				Check: r.TestMatchResourceAttr("echo.tls_public_key_test", "data.public_key_openssh", regexp.MustCompile(` test@test\n$`)),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				// Ephemeral resources are only available in 1.10 and later
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_10_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"echo": echoprovider.NewProviderServer(),
				},
				Steps: []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_ephemeral_errorCases(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "both PEM and OpenSSH PEM",
			step: r.TestStep{
				Config: `
					ephemeral "tls_public_key" "test" {
						private_key_pem = "does not matter"
						private_key_openssh = "does not matter"
					}
				`,
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
		},
		{
			desc: "neither PEM nor OpenSSH PEM",
			step: r.TestStep{
				Config: `
					ephemeral "tls_public_key" "test" {
					}
				`,
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				// Ephemeral resources are only available in 1.10 and later
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_10_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				ProtoV6ProviderFactories: map[string]func() (tfprotov6.ProviderServer, error){
					"echo": echoprovider.NewProviderServer(),
				},
				Steps: []r.TestStep{c.step},
			})
		})
	}
}

// Adds the test echo provider to enable using state checks with ephemeral resources.
func ephemeralPublicKeyWithEchoConfig(cfg string) string {
	return fmt.Sprintf(`
	%s
	provider "echo" {
		data = ephemeral.tls_public_key.test
	}
	resource "echo" "tls_public_key_test" {}
	`, cfg)
}
