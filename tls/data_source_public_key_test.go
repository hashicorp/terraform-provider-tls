package tls

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform/helper/resource"
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

func TestAccPublicKey_dataSource(t *testing.T) {
	resource.Test(t, resource.TestCase{
		Providers: testProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: fmt.Sprintf(testAccDataSourcePublicKeyConfig, testPrivateKey),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_pem", strings.TrimSpace(expectedPublic)+"\n"),
					resource.TestCheckResourceAttr("data.tls_public_key.test", "public_key_openssh", strings.TrimSpace(expectedPublicSSH)+"\n"),
				),
			},
			resource.TestStep{
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
					data "tls_public_key" "test" {
						private_key_pem = "${tls_private_key.test.private_key_pem}"
					}
				`,
				Check: resource.TestCheckResourceAttrPair(
					"data.tls_public_key.test", "public_key_pem",
					"tls_private_key.test", "public_key_pem"),
			},
		},
	})
}

const testAccDataSourcePublicKeyConfig = `
data "tls_public_key" "test" {
  private_key_pem = <<EOF
	%s
	EOF
}
`
