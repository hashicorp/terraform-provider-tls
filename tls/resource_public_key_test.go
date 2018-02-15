package tls

import (
	"fmt"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

const (
	expectedPublic = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDPLaq43D9C596ko9yQipWUf2Fb
RhFs18D3wBDBqXLIoP7W3rm5S292/JiNPa+mX76IYFF416zTBGG9J5w4d4VFrROn
8IuMWqHgdXsCUf2szN7EnJcVBsBzTxxWqz4DjX315vbm/PFOLlKzC0Ngs4h1iDiC
D9Hk2MajZuFnJiqj1QIDAQAB
-----END PUBLIC KEY-----`
	expectedPublicSSH = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQDPLaq43D9C596ko9yQipWUf2FbRhFs18D3wBDBqXLIoP7W3rm5S292/JiNPa+mX76IYFF416zTBGG9J5w4d4VFrROn8IuMWqHgdXsCUf2szN7EnJcVBsBzTxxWqz4DjX315vbm/PFOLlKzC0Ngs4h1iDiCD9Hk2MajZuFnJiqj1Q==`
)

func TestPublicKeyRSA(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: `
					resource "tls_public_key" "test" {
						private_key = <<EOF
						` + testPrivateKey + `
						EOF
					}
					output "private_key_pem" {
						value = "${tls_public_key.test.private_key_pem}"
					}
					output "public_key_pem" {
						value = "${tls_public_key.test.public_key_pem}"
					}
					output "public_key_openssh" {
						value = "${tls_public_key.test.public_key_openssh}"
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
					if !strings.EqualFold(strings.TrimSpace(gotPublic), strings.TrimSpace(expectedPublic)) {
						return fmt.Errorf("expected public key \n%s\ngot public key \n%s", expectedPublic, gotPublic)
					}

					gotPublicSSHUntyped := s.RootModule().Outputs["public_key_openssh"].Value
					gotPublicSSH, ok := gotPublicSSHUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"public_key_openssh\" is not a string")
					}
					if !strings.HasPrefix(gotPublicSSH, "ssh-rsa ") {
						return fmt.Errorf("SSH public key is missing ssh-rsa prefix")
					}
					if !strings.EqualFold(strings.TrimSpace(gotPublicSSH), strings.TrimSpace(expectedPublicSSH)) {
						return fmt.Errorf("expected public OpenSSH \n%s\n got public OpenSSH \n%s", expectedPublicSSH, gotPublicSSH)
					}

					return nil
				},
			},
		},
	})
}
