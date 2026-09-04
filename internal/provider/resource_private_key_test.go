// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"fmt"
	"regexp"
	"testing"

	r "github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	tu "github.com/hashicorp/terraform-provider-tls/internal/provider/testutils"
)

func TestPrivateKeyRSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
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
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
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

func TestAccPrivateKeyRSA_UpgradeFromVersion3_4_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion340(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				ConfigPlanChecks: r.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
		},
	})
}

func TestAccPrivateKeyRSA_UpgradeFromVersion3_1_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion310(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_openssh"),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestCheckNoResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
				`,
				ConfigPlanChecks: r.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyRSA.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "private_key_pem", func(pem string) error {
						if len(pem) > 1700 {
							return fmt.Errorf("private key PEM looks too long for a 2048-bit key (got %v characters)", len(pem))
						}
						return nil
					}),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-rsa `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
		},
	})
}

func TestPrivateKeyECDSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
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
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ecdsa-sha2-nistp256 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
		},
	})
}

func TestAccPrivateKeyECDSA_UpgradeFromVersion3_4_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion340(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", ""),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
				`,
				ConfigPlanChecks: r.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", ""),
				),
			},
		},
	})
}

func TestAccPrivateKeyECDSA_UpgradeFromVersion3_1_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion310(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_openssh"),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ecdsa-sha2-nistp256 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestCheckNoResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256"),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
						ecdsa_curve = "P256"
					}
				`,
				ConfigPlanChecks: r.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyEC.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
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
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
		},
	})
}

func TestPrivateKeyMLDSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ML-DSA-44"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					// `x/crypto/ssh` has no key type for ML-DSA, so all the OpenSSH attributes are empty
					r.TestCheckResourceAttr("tls_private_key.test", "private_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_openssh", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", ""),
					r.TestCheckResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", ""),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ML-DSA-65"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					// The private key is a 32-byte seed regardless of parameter set, so the public
					// key is what has to grow with it: ML-DSA-65 public keys are 1952 bytes.
					r.TestCheckResourceAttrWith("tls_private_key.test", "public_key_pem", func(pem string) error {
						if len(pem) < 2600 {
							return fmt.Errorf("public key PEM looks too short for ML-DSA-65 (got %v characters)", len(pem))
						}
						return nil
					}),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ML-DSA-87"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					r.TestCheckResourceAttrWith("tls_private_key.test", "public_key_pem", func(pem string) error {
						if len(pem) < 3500 {
							return fmt.Errorf("public key PEM looks too short for ML-DSA-87 (got %v characters)", len(pem))
						}
						return nil
					}),
				),
			},
		},
	})
}

// TestAccPrivateKey_UpgradeFromVersion4_3_0 guards the addition of the ML-DSA
// algorithms. `algorithm` carries a RequiresReplace, and keys are the one thing this
// provider must never silently regenerate, so widening the set of accepted values must
// leave keys created by the previous release entirely alone.
func TestAccPrivateKey_UpgradeFromVersion4_3_0(t *testing.T) {
	for _, algorithm := range []string{"RSA", "ECDSA", "ED25519"} {
		t.Run(algorithm, func(t *testing.T) {
			config := fmt.Sprintf(`
					resource "tls_private_key" "test" {
						algorithm = %q
					}
				`, algorithm)

			r.Test(t, r.TestCase{
				Steps: []r.TestStep{
					{
						ExternalProviders: providerVersion430(),
						Config:            config,
					},
					{
						ProtoV5ProviderFactories: protoV5ProviderFactories(),
						Config:                   config,
						ConfigPlanChecks: r.ConfigPlanChecks{
							PreApply: []plancheck.PlanCheck{
								plancheck.ExpectEmptyPlan(),
							},
						},
					},
				},
			})
		})
	}
}

func TestPrivateKeyMLDSA_UnsupportedParameterSet(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ML-DSA-1024"
					}
				`,
				ExpectError: regexp.MustCompile(`Attribute algorithm value must be one of`),
			},
		},
	})
}

func TestAccPrivateKeyED25519_UpgradeFromVersion3_4_0(t *testing.T) {
	r.Test(t, r.TestCase{
		Steps: []r.TestStep{
			{
				ExternalProviders: providerVersion340(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					r.TestCheckNoResourceAttr("tls_private_key.test", "private_key_pem_pkcs8"),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
			{
				ProtoV5ProviderFactories: protoV5ProviderFactories(),
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ConfigPlanChecks: r.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{
						plancheck.ExpectEmptyPlan(),
					},
				},
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem", PreamblePrivateKeyPKCS8.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "public_key_pem", PreamblePublicKey.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_openssh", PreamblePrivateKeyOpenSSH.String()),
					tu.TestCheckPEMFormat("tls_private_key.test", "private_key_pem_pkcs8", PreamblePrivateKeyPKCS8.String()),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_openssh", regexp.MustCompile(`^ssh-ed25519 `)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_md5", regexp.MustCompile(`^([abcdef\d]{2}:){15}[abcdef\d]{2}`)),
					r.TestMatchResourceAttr("tls_private_key.test", "public_key_fingerprint_sha256", regexp.MustCompile(`^SHA256:`)),
				),
			},
		},
	})
}
