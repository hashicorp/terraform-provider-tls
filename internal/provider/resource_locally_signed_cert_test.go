package provider

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"testing"
	"time"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestLocallySignedCert(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: locallySignedCertConfig(1, 0),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMFormat("tls_locally_signed_cert.test", "cert_pem", PreambleCertificate),
					testCheckPEMCertificateSubject("tls_locally_signed_cert.test", "cert_pem", &pkix.Name{
						SerialNumber:       "2",
						CommonName:         "example.com",
						Organization:       []string{"Example, Inc"},
						OrganizationalUnit: []string{"Department of Terraform Testing"},
						StreetAddress:      []string{"5879 Cotton Link"},
						Locality:           []string{"Pirate Harbor"},
						Province:           []string{"CA"},
						Country:            []string{"US"},
						PostalCode:         []string{"95559-1227"},
					}),
					testCheckPEMCertificateDNSNames("tls_locally_signed_cert.test", "cert_pem", []string{
						"example.com",
						"example.net",
					}),
					testCheckPEMCertificateIPAddresses("tls_locally_signed_cert.test", "cert_pem", []net.IP{
						net.ParseIP("127.0.0.1"),
						net.ParseIP("127.0.0.2"),
					}),
					testCheckPEMCertificateURIs("tls_locally_signed_cert.test", "cert_pem", []*url.URL{
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "workload",
						},
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "workload2",
						},
					}),
					testCheckPEMCertificateKeyUsage("tls_locally_signed_cert.test", "cert_pem", x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature),
					testCheckPEMCertificateExtKeyUsages("tls_locally_signed_cert.test", "cert_pem", []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
						x509.ExtKeyUsageClientAuth,
					}),
					testCheckPEMCertificateAgainstPEMRootCA("tls_locally_signed_cert.test", "cert_pem", []byte(testCACert)),
					testCheckPEMCertificateDuration("tls_locally_signed_cert.test", "cert_pem", time.Hour),
				),
			},
		},
	})
}

func TestAccLocallySignedCertRecreatesAfterExpired(t *testing.T) {
	oldNow := overridableTimeFunc
	var previousCert string
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		PreCheck:          setTimeForTest("2019-06-14T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: locallySignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					previousCert = value
					return nil
				}),
			},
			{
				Config: locallySignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					if value != previousCert {
						return fmt.Errorf("certificate updated even though no time has passed")
					}
					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T19:00:00Z"),
				Config:    locallySignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					if value != previousCert {
						return fmt.Errorf("certificate updated even though not enough time has passed")
					}
					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T21:00:00Z"),
				Config:    locallySignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					if value == previousCert {
						return fmt.Errorf("certificate not updated even though passed early renewal")
					}
					previousCert = value
					return nil
				}),
			},
		},
	})
	overridableTimeFunc = oldNow
}

func TestAccLocallySignedCertNotRecreatedForEarlyRenewalUpdateInFuture(t *testing.T) {
	oldNow := overridableTimeFunc
	var previousCert string
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		PreCheck:          setTimeForTest("2019-06-14T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: locallySignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					previousCert = value
					return nil
				}),
			},
			{
				Config: locallySignedCertConfig(10, 3),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					if value != previousCert {
						return fmt.Errorf("certificate updated even though still time until early renewal")
					}
					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T16:00:00Z"),
				Config:    locallySignedCertConfig(10, 3),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					if value != previousCert {
						return fmt.Errorf("certificate updated even though still time until early renewal")
					}
					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T16:00:00Z"),
				Config:    locallySignedCertConfig(10, 9),
				Check: r.TestCheckResourceAttrWith("tls_locally_signed_cert.test", "cert_pem", func(value string) error {
					if value == previousCert {
						return fmt.Errorf("certificate not updated even though early renewal time has passed")
					}
					previousCert = value
					return nil
				}),
			},
		},
	})
	overridableTimeFunc = oldNow
}

// TODO Remove this as part of https://github.com/hashicorp/terraform-provider-tls/issues/174
func TestAccLocallySignedCert_HandleKeyAlgorithmDeprecation(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: locallySignedCertConfigWithDeprecatedKeyAlgorithm(1, 0),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMFormat("tls_locally_signed_cert.test", "cert_pem", PreambleCertificate),
					testCheckPEMCertificateSubject("tls_locally_signed_cert.test", "cert_pem", &pkix.Name{
						SerialNumber:       "2",
						CommonName:         "example.com",
						Organization:       []string{"Example, Inc"},
						OrganizationalUnit: []string{"Department of Terraform Testing"},
						StreetAddress:      []string{"5879 Cotton Link"},
						Locality:           []string{"Pirate Harbor"},
						Province:           []string{"CA"},
						Country:            []string{"US"},
						PostalCode:         []string{"95559-1227"},
					}),
					testCheckPEMCertificateDNSNames("tls_locally_signed_cert.test", "cert_pem", []string{
						"example.com",
						"example.net",
					}),
					testCheckPEMCertificateIPAddresses("tls_locally_signed_cert.test", "cert_pem", []net.IP{
						net.ParseIP("127.0.0.1"),
						net.ParseIP("127.0.0.2"),
					}),
					testCheckPEMCertificateURIs("tls_locally_signed_cert.test", "cert_pem", []*url.URL{
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "workload",
						},
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "workload2",
						},
					}),
					testCheckPEMCertificateKeyUsage("tls_locally_signed_cert.test", "cert_pem", x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature),
					testCheckPEMCertificateExtKeyUsages("tls_locally_signed_cert.test", "cert_pem", []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
						x509.ExtKeyUsageClientAuth,
					}),
					testCheckPEMCertificateAgainstPEMRootCA("tls_locally_signed_cert.test", "cert_pem", []byte(testCACert)),
					testCheckPEMCertificateDuration("tls_locally_signed_cert.test", "cert_pem", time.Hour),
				),
			},
		},
	})
}

func locallySignedCertConfig(validity, earlyRenewal uint32) string {
	return fmt.Sprintf(`
        resource "tls_locally_signed_cert" "test" {
            cert_request_pem = <<EOT
%s
EOT
            validity_period_hours = %d
            early_renewal_hours = %d
            allowed_uses = [
                "key_encipherment",
                "digital_signature",
                "server_auth",
                "client_auth",
            ]
            ca_cert_pem = <<EOT
%s
EOT
            ca_private_key_pem = <<EOT
%s
EOT
        }`, testCertRequest, validity, earlyRenewal, testCACert, testCAPrivateKey)
}

func locallySignedCertConfigWithDeprecatedKeyAlgorithm(validity, earlyRenewal uint32) string {
	return fmt.Sprintf(`
        resource "tls_locally_signed_cert" "test" {
            cert_request_pem = <<EOT
%s
EOT
            validity_period_hours = %d
            early_renewal_hours = %d
            allowed_uses = [
                "key_encipherment",
                "digital_signature",
                "server_auth",
                "client_auth",
            ]
            ca_cert_pem = <<EOT
%s
EOT
            ca_key_algorithm = "RSA"
            ca_private_key_pem = <<EOT
%s
EOT
        }`, testCertRequest, validity, earlyRenewal, testCACert, testCAPrivateKey)
}

func TestAccResourceLocallySignedCert_FromED25519PrivateKeyResource(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "ca_prv_test" {
						algorithm = "ED25519"
					}
					resource "tls_self_signed_cert" "ca_cert_test" {
						private_key_pem = tls_private_key.ca_prv_test.private_key_pem
						subject {
							organization = "test-organization"
						}
						is_ca_certificate     = true
						validity_period_hours = 8760
						allowed_uses = [
							"cert_signing",
						]
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_cert_request" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						subject {
							common_name  = "test.com"
						}
					}
					resource "tls_locally_signed_cert" "test" {
						validity_period_hours = 1
						early_renewal_hours = 0
						allowed_uses = [
							"server_auth",
							"client_auth",
						]
						cert_request_pem = tls_cert_request.test.cert_request_pem
						ca_cert_pem = tls_self_signed_cert.ca_cert_test.cert_pem
						ca_private_key_pem = tls_private_key.ca_prv_test.private_key_pem
					}
				`,
				Check: r.ComposeTestCheckFunc(
					r.TestCheckResourceAttr("tls_locally_signed_cert.test", "ca_key_algorithm", "ED25519"),
					testCheckPEMFormat("tls_locally_signed_cert.test", "cert_pem", PreambleCertificate),
				),
			},
		},
	})
}

func TestAccResourceLocallySignedCert_FromECDSAPrivateKeyResource(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "ca_prv_test" {
						algorithm = "ECDSA"
					}
					resource "tls_self_signed_cert" "ca_cert_test" {
						private_key_pem = tls_private_key.ca_prv_test.private_key_pem
						subject {
							organization = "test-organization"
						}
						is_ca_certificate     = true
						validity_period_hours = 8760
						allowed_uses = [
							"cert_signing",
						]
					}
					resource "tls_private_key" "test" {
						algorithm = "ECDSA"
					}
					resource "tls_cert_request" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						subject {
							common_name  = "test.com"
						}
					}
					resource "tls_locally_signed_cert" "test" {
						validity_period_hours = 1
						early_renewal_hours = 0
						allowed_uses = [
							"server_auth",
							"client_auth",
						]
						cert_request_pem = tls_cert_request.test.cert_request_pem
						ca_cert_pem = tls_self_signed_cert.ca_cert_test.cert_pem
						ca_private_key_pem = tls_private_key.ca_prv_test.private_key_pem
					}
				`,
				Check: r.ComposeTestCheckFunc(
					r.TestCheckResourceAttr("tls_locally_signed_cert.test", "ca_key_algorithm", "ECDSA"),
					testCheckPEMFormat("tls_locally_signed_cert.test", "cert_pem", PreambleCertificate),
				),
			},
		},
	})
}

func TestAccResourceLocallySignedCert_FromRSAPrivateKeyResource(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "ca_prv_test" {
						algorithm = "RSA"
					}
					resource "tls_self_signed_cert" "ca_cert_test" {
						private_key_pem = tls_private_key.ca_prv_test.private_key_pem
						subject {
							organization = "test-organization"
						}
						is_ca_certificate     = true
						validity_period_hours = 8760
						allowed_uses = [
							"cert_signing",
						]
					}
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					resource "tls_cert_request" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						subject {
							common_name  = "test.com"
						}
					}
					resource "tls_locally_signed_cert" "test" {
						validity_period_hours = 1
						early_renewal_hours = 0
						allowed_uses = [
							"server_auth",
							"client_auth",
						]
						cert_request_pem = tls_cert_request.test.cert_request_pem
						ca_cert_pem = tls_self_signed_cert.ca_cert_test.cert_pem
						ca_private_key_pem = tls_private_key.ca_prv_test.private_key_pem
					}
				`,
				Check: r.ComposeTestCheckFunc(
					r.TestCheckResourceAttr("tls_locally_signed_cert.test", "ca_key_algorithm", "RSA"),
					testCheckPEMFormat("tls_locally_signed_cert.test", "cert_pem", PreambleCertificate),
				),
			},
		},
	})
}
