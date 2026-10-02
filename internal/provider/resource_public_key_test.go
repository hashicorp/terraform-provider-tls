// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/fixtures"
)

const (
	configResourcePublicKeyViaPEM = `
resource "tls_public_key" "test" {
	private_key_pem_wo = <<EOF
	%s
	EOF
}
`
	configResourcePublicKeyViaOpenSSHPEM = `
resource "tls_public_key" "test" {
	private_key_openssh_wo = <<EOF
	%s
	EOF
}
`
)

func TestPublicKey_resource_PEM(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "literal RSA PEM",
			step: r.TestStep{
				Config: fmt.Sprintf(configResourcePublicKeyViaPEM, fixtures.TestPrivateKeyPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_pem", strings.TrimSpace(fixtures.TestPublicKeyPEM)+"\n"),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_openssh", strings.TrimSpace(fixtures.TestPublicKeyOpenSSH)+"\n"),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_fingerprint_md5", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintMD5)),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_fingerprint_sha256", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintSHA256)),
					r.TestCheckResourceAttr("tls_public_key.test", "algorithm", "RSA"),
				),
			},
		},
		{
			desc: "RSA PEM from resource",
			step: r.TestStep{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					resource "tls_public_key" "test" {
						private_key_pem_wo = tls_private_key.test.private_key_pem
					}
				`,
				Check: r.TestCheckResourceAttrPair(
					"tls_public_key.test", "public_key_pem",
					"tls_private_key.test", "public_key_pem",
				),
			},
		},
		{
			desc: "ECDSA P384 PEM from resource",
			step: r.TestStep{
				Config: `
					resource "tls_private_key" "ecdsaPrvKey" {
						algorithm   = "ECDSA"
						ecdsa_curve = "P384"
					}
					resource "tls_public_key" "test" {
						private_key_pem_wo = tls_private_key.ecdsaPrvKey.private_key_pem
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttrPair(
						"tls_public_key.test", "public_key_pem",
						"tls_private_key.ecdsaPrvKey", "public_key_pem",
					),
					r.TestCheckResourceAttr("tls_public_key.test", "algorithm", "ECDSA"),
				),
			},
		},
		{
			desc: "corrupt PEM",
			step: r.TestStep{
				Config:      fmt.Sprintf(configResourcePublicKeyViaPEM, "corrupt"),
				ExpectError: regexp.MustCompile(`failed to decode PEM block: decoded bytes \d, undecoded \d`),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_11_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Steps:                    []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_resource_OpenSSHPEM(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "literal RSA OpenSSH PEM",
			step: r.TestStep{
				Config: fmt.Sprintf(configResourcePublicKeyViaOpenSSHPEM, fixtures.TestPrivateKeyOpenSSHPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_pem", strings.TrimSpace(fixtures.TestPublicKeyPEM)+"\n"),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_openssh", strings.TrimSpace(fixtures.TestPublicKeyOpenSSH)+"\n"),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_fingerprint_md5", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintMD5)),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_fingerprint_sha256", strings.TrimSpace(fixtures.TestPublicKeyOpenSSHFingerprintSHA256)),
					r.TestCheckResourceAttr("tls_public_key.test", "algorithm", "RSA"),
				),
			},
		},
		{
			desc: "RSA OpenSSH PEM from resource",
			step: r.TestStep{
				Config: `
					resource "tls_private_key" "rsaPrvKey" {
						algorithm = "RSA"
					}
					resource "tls_public_key" "test" {
						private_key_openssh_wo = tls_private_key.rsaPrvKey.private_key_openssh
					}
				`,
				Check: r.TestCheckResourceAttrPair(
					"tls_public_key.test", "public_key_openssh",
					"tls_private_key.rsaPrvKey", "public_key_openssh",
				),
			},
		},
		{
			desc: "ED25519 OpenSSH PEM from resource",
			step: r.TestStep{
				Config: `
					resource "tls_private_key" "ed25519PrvKey" {
						algorithm   = "ED25519"
					}
					resource "tls_public_key" "test" {
						private_key_openssh_wo = tls_private_key.ed25519PrvKey.private_key_openssh
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttrPair(
						"tls_public_key.test", "public_key_openssh",
						"tls_private_key.ed25519PrvKey", "public_key_openssh",
					),
					r.TestCheckResourceAttr("tls_public_key.test", "algorithm", "ED25519"),
				),
			},
		},
		{
			desc: "corrupt OpenSSH PEM",
			step: r.TestStep{
				Config:      fmt.Sprintf(configResourcePublicKeyViaOpenSSHPEM, "corrupt"),
				ExpectError: regexp.MustCompile("ssh: no key found"),
			},
		},
	}

	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_11_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Steps:                    []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_resource_PKCS8PEM(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "RSA PKCS8 PEM from resource",
			step: r.TestStep{
				Config: `
					resource "tls_private_key" "rsaPrvKey" {
						algorithm = "RSA"
					}
					resource "tls_public_key" "test" {
						private_key_pem_wo = tls_private_key.rsaPrvKey.private_key_pem_pkcs8
					}
				`,
				Check: r.TestCheckResourceAttrPair(
					"tls_public_key.test", "public_key_openssh",
					"tls_private_key.rsaPrvKey", "public_key_openssh",
				),
			},
		},
		{
			desc: "ED25519 PKCS8 PEM from resource",
			step: r.TestStep{
				Config: `
					resource "tls_private_key" "ed25519PrvKey" {
						algorithm   = "ED25519"
					}
					resource "tls_public_key" "test" {
						private_key_pem_wo = tls_private_key.ed25519PrvKey.private_key_pem_pkcs8
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttrPair(
						"tls_public_key.test", "public_key_openssh",
						"tls_private_key.ed25519PrvKey", "public_key_openssh",
					),
					r.TestCheckResourceAttr("tls_public_key.test", "algorithm", "ED25519"),
				),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_11_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Steps:                    []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_resource_errorCases(t *testing.T) {
	cases := []struct {
		desc string
		step r.TestStep
	}{
		{
			desc: "both PEM and OpenSSH PEM",
			step: r.TestStep{
				Config: `
					resource "tls_public_key" "test" {
						private_key_pem_wo = "does not matter"
						private_key_openssh_wo = "does not matter"
					}
				`,
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
		},
		{
			desc: "neither PEM nor OpenSSH PEM",
			step: r.TestStep{
				Config: `
					resource "tls_public_key" "test" {
					}
				`,
				ExpectError: regexp.MustCompile("Invalid Attribute Combination"),
			},
		},
	}
	for _, c := range cases {
		t.Run(c.desc, func(t *testing.T) {
			r.UnitTest(t, r.TestCase{
				TerraformVersionChecks: []tfversion.TerraformVersionCheck{
					tfversion.SkipBelow(tfversion.Version1_11_0),
				},
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Steps:                    []r.TestStep{c.step},
			})
		})
	}
}

func TestPublicKey_resource_woVersionChange(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		TerraformVersionChecks: []tfversion.TerraformVersionCheck{
			tfversion.SkipBelow(tfversion.Version1_11_0),
		},
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
					resource "tls_public_key" "test" {
						private_key_pem_wo = <<EOF
						%s
						EOF
						private_key_wo_version = 1
					}
				`, fixtures.TestPrivateKeyPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_public_key.test", "algorithm", "RSA"),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_pem", strings.TrimSpace(fixtures.TestPublicKeyPEM)+"\n"),
				),
			},
			{
				Config: fmt.Sprintf(`
					resource "tls_public_key" "test" {
						private_key_pem_wo = <<EOF
						%s
						EOF
						private_key_wo_version = 2
					}
				`, fixtures.TestPrivateKeyPEM),
				ConfigPlanChecks: r.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectResourceAction("tls_public_key.test", plancheck.ResourceActionReplace),
					},
				},
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_public_key.test", "algorithm", "RSA"),
					r.TestCheckResourceAttr("tls_public_key.test", "public_key_pem", strings.TrimSpace(fixtures.TestPublicKeyPEM)+"\n"),
				),
			},
		},
	})
}
