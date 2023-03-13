package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/fixtures"
)

const (
	configDataSourceEncryptedPEM = `
resource "tls_encrypted_pem" "test" {
	password = "%s"
	pem = <<EOF
%s
EOF
}
`
	configDataSourceEncryptedPEMWithCipher = `
resource "tls_encrypted_pem" "test" {
	password = "%s"
	cipher = "%s"
	pem = <<EOF
%s
EOF
}
`

	encryptedPEMHeaderPrefixAES256 = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,"
	encryptedPEMHeaderPrefixAES192 = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-192-CBC,"
	encryptedPEMHeaderPrefixAES128 = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,"
	encryptedPEMHeaderPrefix3DES   = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: DES-EDE3-CBC,"
)

func checkEncryptedPEMHeader(cipher string) r.CheckResourceAttrWithFunc {
	return func(pem string) error {
		switch cipher {
		case "AES256":
			if !strings.HasPrefix(pem, encryptedPEMHeaderPrefixAES256) {
				return fmt.Errorf("expected the pem to begin with '%s', but got '%s'", encryptedPEMHeaderPrefixAES256, pem)
			}
		case "AES192":
			if !strings.HasPrefix(pem, encryptedPEMHeaderPrefixAES192) {
				return fmt.Errorf("expected the pem to begin with '%s', but got '%s'", encryptedPEMHeaderPrefixAES192, pem)
			}
		case "AES128":
			if !strings.HasPrefix(pem, encryptedPEMHeaderPrefixAES128) {
				return fmt.Errorf("expected the pem to begin with '%s', but got '%s'", encryptedPEMHeaderPrefixAES128, pem)
			}
		case "3DES":
			if !strings.HasPrefix(pem, encryptedPEMHeaderPrefix3DES) {
				return fmt.Errorf("expected the pem to begin with '%s', but got '%s'", encryptedPEMHeaderPrefix3DES, pem)
			}
		default:
			return fmt.Errorf("invalid test setup: unsupported cipher '%s'", cipher)
		}
		return nil
	}
}

func TestEncryptedPEM_dataSource_PEM(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(configDataSourceEncryptedPEM, fixtures.TestEncryptedPEMPassword, strings.TrimSpace(fixtures.TestPrivateKeyPEM)),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "pem", strings.TrimSpace(fixtures.TestPrivateKeyPEM)+"\n"),
					r.TestCheckResourceAttrWith("tls_encrypted_pem.test", "encrypted_pem", checkEncryptedPEMHeader("AES256")),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "password", strings.TrimSpace(fixtures.TestEncryptedPEMPassword)),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "cipher", "AES256"),
				),
			},
			{
				Config: fmt.Sprintf(configDataSourceEncryptedPEMWithCipher, fixtures.TestEncryptedPEMPassword, "AES256", strings.TrimSpace(fixtures.TestPrivateKeyPEM)),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "pem", strings.TrimSpace(fixtures.TestPrivateKeyPEM)+"\n"),
					r.TestCheckResourceAttrWith("tls_encrypted_pem.test", "encrypted_pem", checkEncryptedPEMHeader("AES256")),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "password", strings.TrimSpace(fixtures.TestEncryptedPEMPassword)),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "cipher", "AES256"),
				),
			},
			{
				Config: fmt.Sprintf(configDataSourceEncryptedPEMWithCipher, fixtures.TestEncryptedPEMPassword, "AES192", strings.TrimSpace(fixtures.TestPrivateKeyPEM)),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "pem", strings.TrimSpace(fixtures.TestPrivateKeyPEM)+"\n"),
					r.TestCheckResourceAttrWith("tls_encrypted_pem.test", "encrypted_pem", checkEncryptedPEMHeader("AES192")),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "password", strings.TrimSpace(fixtures.TestEncryptedPEMPassword)),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "cipher", "AES192"),
				),
			},
			{
				Config: fmt.Sprintf(configDataSourceEncryptedPEMWithCipher, fixtures.TestEncryptedPEMPassword, "AES128", strings.TrimSpace(fixtures.TestPrivateKeyPEM)),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "pem", strings.TrimSpace(fixtures.TestPrivateKeyPEM)+"\n"),
					r.TestCheckResourceAttrWith("tls_encrypted_pem.test", "encrypted_pem", checkEncryptedPEMHeader("AES128")),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "password", strings.TrimSpace(fixtures.TestEncryptedPEMPassword)),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "cipher", "AES128"),
				),
			},
			{
				Config: fmt.Sprintf(configDataSourceEncryptedPEMWithCipher, fixtures.TestEncryptedPEMPassword, "3DES", strings.TrimSpace(fixtures.TestPrivateKeyPEM)),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "pem", strings.TrimSpace(fixtures.TestPrivateKeyPEM)+"\n"),
					r.TestCheckResourceAttrWith("tls_encrypted_pem.test", "encrypted_pem", checkEncryptedPEMHeader("3DES")),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "password", strings.TrimSpace(fixtures.TestEncryptedPEMPassword)),
					r.TestCheckResourceAttr("tls_encrypted_pem.test", "cipher", "3DES"),
				),
			},
			{
				Config:      fmt.Sprintf(configDataSourceEncryptedPEM, fixtures.TestEncryptedPEMPassword, "corrupt"),
				ExpectError: regexp.MustCompile(`failed to decode PEM block: decoded bytes \d, undecoded \d`),
			},
		},
	})
}

func TestEncryptedPEM_dataSource_errorCases(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV5ProviderFactories: protoV5ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_encrypted_pem" "test" {
						pem = "does not matter"
					}
				`,
				ExpectError: regexp.MustCompile("The argument \"password\" is required, but no definition was found."),
			},
			{
				Config: `
					resource "tls_encrypted_pem" "test" {
						pem      = "does not matter"
						password = "does not matter"
						cipher   = "invalid"
					}
				`,
				ExpectError: regexp.MustCompile("Attribute cipher value must be one of"),
			},
		},
	})
}
