package provider

import (
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

func TestPrivateKeyRSA(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
                    resource "tls_private_key" "test" {
                        algorithm = "RSA"
                    }
                    output "private_key_pem" {
                        value = "${tls_private_key.test.private_key_pem}"
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
                `,
				Check: func(s *terraform.State) error {
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

					gotPublicUntyped := s.RootModule().Outputs["public_key_pem"].Value
					gotPublic, ok := gotPublicUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPublic, "-----BEGIN PUBLIC KEY----") {
						return fmt.Errorf("public key is missing public key PEM preamble")
					}

					gotPublicSSHUntyped := s.RootModule().Outputs["public_key_openssh"].Value
					gotPublicSSH, ok := gotPublicSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPublicSSH, "ssh-rsa ") {
						return fmt.Errorf("SSH public key is missing ssh-rsa prefix")
					}

					gotPublicFingerprintUntyped := s.RootModule().Outputs["public_key_fingerprint_md5"].Value
					gotPublicFingerprint, ok := gotPublicFingerprintUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_md5\" is not a string")
					}
					if !(gotPublicFingerprint[2] == ':') {
						return fmt.Errorf("MD5 public key fingerprint is missing : in the correct place")
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
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
                    resource "tls_private_key" "test" {
                        algorithm = "ECDSA"
                    }
                    output "private_key_pem" {
                        value = "${tls_private_key.test.private_key_pem}"
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
                `,
				Check: func(s *terraform.State) error {
					gotPrivateUntyped := s.RootModule().Outputs["private_key_pem"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_pem\" is not a string")
					}

					if !strings.HasPrefix(gotPrivate, "-----BEGIN EC PRIVATE KEY----") {
						return fmt.Errorf("Private key is missing EC key PEM preamble")
					}

					gotPublicUntyped := s.RootModule().Outputs["public_key_pem"].Value
					gotPublic, ok := gotPublicUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_pem\" is not a string")
					}

					if !strings.HasPrefix(gotPublic, "-----BEGIN PUBLIC KEY----") {
						return fmt.Errorf("public key is missing public key PEM preamble")
					}

					gotPublicSSH := s.RootModule().Outputs["public_key_openssh"].Value.(string)
					if gotPublicSSH != "" {
						return fmt.Errorf("P224 EC key should not generate OpenSSH public key")
					}

					gotPublicFingerprint := s.RootModule().Outputs["public_key_fingerprint_md5"].Value.(string)
					if gotPublicFingerprint != "" {
						return fmt.Errorf("P224 EC key should not generate OpenSSH public key fingerprint")
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
                `,
				Check: func(s *terraform.State) error {
					gotPrivateUntyped := s.RootModule().Outputs["private_key_pem"].Value
					gotPrivate, ok := gotPrivateUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"private_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPrivate, "-----BEGIN EC PRIVATE KEY----") {
						return fmt.Errorf("Private key is missing EC key PEM preamble")
					}

					gotPublicUntyped := s.RootModule().Outputs["public_key_pem"].Value
					gotPublic, ok := gotPublicUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_pem\" is not a string")
					}
					if !strings.HasPrefix(gotPublic, "-----BEGIN PUBLIC KEY----") {
						return fmt.Errorf("public key is missing public key PEM preamble")
					}

					gotPublicSSHUntyped := s.RootModule().Outputs["public_key_openssh"].Value
					gotPublicSSH, ok := gotPublicSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPublicSSH, "ecdsa-sha2-nistp256 ") {
						return fmt.Errorf("P256 SSH public key is missing ecdsa prefix")
					}

					gotPublicFingerprintUntyped := s.RootModule().Outputs["public_key_fingerprint_md5"].Value
					gotPublicFingerprint, ok := gotPublicFingerprintUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_fingerprint_md5\" is not a string")
					}
					if !(gotPublicFingerprint[2] == ':') {
						return fmt.Errorf("MD5 public key fingerprint is missing : in the correct planbe")
					}

					return nil
				},
			},
		},
	})
}

type keyLens struct {
	algorithm   string
	rsa_bits    int
	ecdsa_curve string
}

var testAccProviders map[string]*schema.Provider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = New()
	testAccProviders = map[string]*schema.Provider{
		"tls": testAccProvider,
	}
}

func TestAccImportKey(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		PreCheck:  func() {},
		Providers: testAccProviders,
		Steps: []r.TestStep{
			{
				Config: testAccResourceKeyConfig,
				Check: r.ComposeTestCheckFunc(
					testAccResourceKeyCheck("tls_private_key.rsa", &keyLens{
						algorithm:   "RSA",
						rsa_bits:    2048,
						ecdsa_curve: "P224",
					}),
					testAccResourceKeyCheck("tls_private_key.ecdsa", &keyLens{
						algorithm:   "ECDSA",
						rsa_bits:    2048,
						ecdsa_curve: "P224",
					}),
				),
			},
			{
				ResourceName:      "tls_private_key.rsa",
				ImportState:       true,
				ImportStateIdFunc: importStateIdFunc(t, testPrivateKey),
			},
			{
				ResourceName:      "tls_private_key.ecdsa",
				ImportState:       true,
				ImportStateIdFunc: importStateIdFunc(t, testPrivateKeyECDSA),
			},
		},
	})
}
func importStateIdFunc(t *testing.T, key string) func(*terraform.State) (string, error) {
	return func(state *terraform.State) (string, error) {
		file, err := ioutil.TempFile(t.TempDir(), state.Lineage)
		file.Write([]byte(key))
		if err != nil {
			return "", fmt.Errorf("could not write file: %w", err)
		}
		return file.Name(), nil
	}
}
func testAccResourceKeyCheck(id string, want *keyLens) r.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[id]
		if !ok {
			return fmt.Errorf("Not found: %s", id)
		}
		if rs.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		algorithm := rs.Primary.Attributes["algorithm"]
		rsa_bits := rs.Primary.Attributes["rsa_bits"]
		ecdsa_curve := rs.Primary.Attributes["ecdsa_curve"]

		if got, want := algorithm, want.algorithm; got != want {
			return fmt.Errorf("algorithm is %s; want %s", got, want)
		}
		if got, want := rsa_bits, want.rsa_bits; got != fmt.Sprint(want) {
			return fmt.Errorf("rsa_bits is %v; want %v", got, want)
		}
		if got, want := ecdsa_curve, want.ecdsa_curve; got != want {
			return fmt.Errorf("ecdsa_curve is %s; want %s", got, want)
		}

		return nil
	}
}

const (
	testAccResourceKeyConfig = `
resource "tls_private_key" "rsa" {
  algorithm = "RSA"
}

resource "tls_private_key" "ecdsa" {
  algorithm = "ECDSA"
}
`
)
