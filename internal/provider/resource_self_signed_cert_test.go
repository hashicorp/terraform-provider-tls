package provider

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"testing"
	"time"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestAccResourceSelfSignedCert(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: selfSignedCertConfig(1, 0),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMFormat("tls_self_signed_cert.test1", "cert_pem", PreambleCertificate),
					testCheckPEMCertificateSubject("tls_self_signed_cert.test1", "cert_pem", &pkix.Name{
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
					testCheckPEMCertificateDNSNames("tls_self_signed_cert.test1", "cert_pem", []string{
						"example.com",
						"example.net",
					}),
					testCheckPEMCertificateIPAddresses("tls_self_signed_cert.test1", "cert_pem", []net.IP{
						net.ParseIP("127.0.0.1"),
						net.ParseIP("127.0.0.2"),
					}),
					testCheckPEMCertificateURIs("tls_self_signed_cert.test1", "cert_pem", []*url.URL{
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "ca",
						},
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "ca2",
						},
					}),
					testCheckPEMCertificateKeyUsage("tls_self_signed_cert.test1", "cert_pem", x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature),
					testCheckPEMCertificateExtKeyUsages("tls_self_signed_cert.test1", "cert_pem", []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
						x509.ExtKeyUsageClientAuth,
					}),
					testCheckPEMCertificateDuration("tls_self_signed_cert.test1", "cert_pem", time.Hour),
				),
			},
			{
				Config: fmt.Sprintf(`
                    resource "tls_self_signed_cert" "test2" {
                        subject {
                            serial_number = "42"
                        }
                        validity_period_hours = 1
                        allowed_uses = []
                        private_key_pem = <<EOT
%s
EOT
                    }
                `, testPrivateKeyPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMFormat("tls_self_signed_cert.test2", "cert_pem", PreambleCertificate),
					testCheckPEMCertificateSubject("tls_self_signed_cert.test2", "cert_pem", &pkix.Name{
						SerialNumber: "42",
					}),
					testCheckPEMCertificateDNSNames("tls_self_signed_cert.test2", "cert_pem", []string{}),
					testCheckPEMCertificateIPAddresses("tls_self_signed_cert.test2", "cert_pem", []net.IP{}),
					testCheckPEMCertificateURIs("tls_self_signed_cert.test2", "cert_pem", []*url.URL{}),
					testCheckPEMCertificateKeyUsage("tls_self_signed_cert.test2", "cert_pem", x509.KeyUsage(0)),
					testCheckPEMCertificateExtKeyUsages("tls_self_signed_cert.test2", "cert_pem", []x509.ExtKeyUsage{}),
				),
			},
		},
	})
}

// TODO Remove this as part of https://github.com/hashicorp/terraform-provider-tls/issues/174
func TestAccResourceSelfSignedCert_HandleKeyAlgorithmDeprecation(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: selfSignedCertConfigWithDeprecatedKeyAlgorithm(1, 0),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMFormat("tls_self_signed_cert.test1", "cert_pem", PreambleCertificate),
					testCheckPEMCertificateSubject("tls_self_signed_cert.test1", "cert_pem", &pkix.Name{
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
					testCheckPEMCertificateDNSNames("tls_self_signed_cert.test1", "cert_pem", []string{
						"example.com",
						"example.net",
					}),
					testCheckPEMCertificateIPAddresses("tls_self_signed_cert.test1", "cert_pem", []net.IP{
						net.ParseIP("127.0.0.1"),
						net.ParseIP("127.0.0.2"),
					}),
					testCheckPEMCertificateURIs("tls_self_signed_cert.test1", "cert_pem", []*url.URL{
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "ca",
						},
						{
							Scheme: "spiffe",
							Host:   "example-trust-domain",
							Path:   "ca2",
						},
					}),
					testCheckPEMCertificateKeyUsage("tls_self_signed_cert.test1", "cert_pem", x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature),
					testCheckPEMCertificateExtKeyUsages("tls_self_signed_cert.test1", "cert_pem", []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
						x509.ExtKeyUsageClientAuth,
					}),
					testCheckPEMCertificateDuration("tls_self_signed_cert.test1", "cert_pem", time.Hour),
				),
			},
		},
	})
}

func TestAccResourceSelfSignedCert_RecreatesAfterExpired(t *testing.T) {
	oldNow := overridableTimeFunc
	var previousCert string
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		PreCheck:          setTimeForTest("2019-06-14T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: selfSignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					previousCert = value
					return nil
				}),
			},
			{
				Config: selfSignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					if previousCert != value {
						return fmt.Errorf("certificate updated even though no time has passed")
					}

					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T19:00:00Z"),
				Config:    selfSignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					if previousCert != value {
						return fmt.Errorf("certificate updated even though not enough time has passed")
					}

					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T21:00:00Z"),
				Config:    selfSignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					if previousCert == value {
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

func TestAccResourceSelfSignedCert_NotRecreatedForEarlyRenewalUpdateInFuture(t *testing.T) {
	oldNow := overridableTimeFunc
	var previousCert string
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		PreCheck:          setTimeForTest("2019-06-14T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: selfSignedCertConfig(10, 2),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					previousCert = value
					return nil
				}),
			},
			{
				Config: selfSignedCertConfig(10, 3),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					if previousCert != value {
						return fmt.Errorf("certificate updated even though still time until early renewal")
					}

					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T16:00:00Z"),
				Config:    selfSignedCertConfig(10, 3),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					if previousCert != value {
						return fmt.Errorf("certificate updated even though still time until early renewal")
					}

					previousCert = value
					return nil
				}),
			},
			{
				PreConfig: setTimeForTest("2019-06-14T16:00:00Z"),
				Config:    selfSignedCertConfig(10, 9),
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
					if previousCert == value {
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

func TestAccResourceSelfSignedCert_KeyIDs(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		PreCheck:          setTimeForTest("2019-06-14T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
					resource "tls_self_signed_cert" "test" {
						subject {
							serial_number = "42"
						}
						validity_period_hours = 1
						allowed_uses = []
						set_subject_key_id = true
						private_key_pem = <<EOT
%s
EOT
					}
				`, testPrivateKeyPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMCertificateSubjectKeyID("tls_self_signed_cert.test", "cert_pem", testPrivateKeyPEMSubjectKeyID),
					testCheckPEMCertificateNoAuthorityKeyID("tls_self_signed_cert.test", "cert_pem"),
				),
			},
			{
				Config: fmt.Sprintf(`
					resource "tls_self_signed_cert" "test" {
						subject {
							serial_number = "42"
						}
						validity_period_hours = 1
						allowed_uses = []
						set_subject_key_id = true
						set_authority_key_id = true
						private_key_pem = <<EOT
%s
EOT
					}
				`, testPrivateKeyPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMCertificateSubjectKeyID("tls_self_signed_cert.test", "cert_pem", testPrivateKeyPEMSubjectKeyID),
					testCheckPEMCertificateAuthorityKeyID("tls_self_signed_cert.test", "cert_pem", testPrivateKeyPEMSubjectKeyID),
				),
			},
		},
	})
}

func TestAccResourceSelfSignedCert_InvalidConfigs(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_self_signed_cert" "test" {
						subject {
							common_name = "common test cert"
						}
						validity_period_hours = -1
						allowed_uses = [
						]
						set_subject_key_id = true
						private_key_pem = "does not matter"
					}
				`,
				ExpectError: regexp.MustCompile(`expected validity_period_hours to be at least \(0\), got -1`),
			},
			{
				Config: `
					resource "tls_self_signed_cert" "test" {
						subject {
							common_name = "common test cert"
						}
						validity_period_hours = 20
						early_renewal_hours = -10
						allowed_uses = [
						]
						set_subject_key_id = true
						private_key_pem = "does not matter"
					}
				`,
				ExpectError: regexp.MustCompile(`expected early_renewal_hours to be at least \(0\), got -10`),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_self_signed_cert" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						set_subject_key_id    = true
						validity_period_hours = 8760
						subject {}
						subject {}
						allowed_uses = [
							"key_encipherment",
						]
						ip_addresses = [
							"127.0.0.2",
						]
					}
				`,
				ExpectError: regexp.MustCompile("Too many (list items|subject blocks)"),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_self_signed_cert" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						is_ca_certificate     = true
						set_subject_key_id    = true
						validity_period_hours = 8760
						allowed_uses = [
							"key_encipherment",
						]
						ip_addresses = [
							"127.0.0.2",
						]
					}
				`,
				ExpectError: regexp.MustCompile(`Certificate Subject must contain at least one Distinguished Name when creating Certificate Authority \(CA\)`),
			},
			{
				Config: fmt.Sprintf(`
					resource "tls_self_signed_cert" "test" {
						subject {
							serial_number = "42"
						}
						validity_period_hours = 1
						allowed_uses = []
						set_authority_key_id = true
						private_key_pem = <<EOT
%s
EOT
					}
				`, testPrivateKeyPEM),
				ExpectError: regexp.MustCompile("could not determine the Authority Key Identifier from the Certificate Authority"),
			},
		},
	})
}

func selfSignedCertConfig(validity, earlyRenewal uint32) string {
	return fmt.Sprintf(`
        resource "tls_self_signed_cert" "test1" {
            subject {
                common_name = "example.com"
                organization = "Example, Inc"
                organizational_unit = "Department of Terraform Testing"
                street_address = ["5879 Cotton Link"]
                locality = "Pirate Harbor"
                province = "CA"
                country = "US"
                postal_code = "95559-1227"
                serial_number = "2"
            }

            dns_names = [
                "example.com",
                "example.net",
            ]

            ip_addresses = [
                "127.0.0.1",
                "127.0.0.2",
            ]

            uris = [
                "spiffe://example-trust-domain/ca",
                "spiffe://example-trust-domain/ca2",
            ]

            validity_period_hours = %d
            early_renewal_hours = %d

            allowed_uses = [
                "key_encipherment",
                "digital_signature",
                "server_auth",
                "client_auth",
                "non_repudiation",
            ]

            private_key_pem = <<EOT
%s
EOT
        }`, validity, earlyRenewal, testPrivateKeyPEM)
}

func selfSignedCertConfigWithDeprecatedKeyAlgorithm(validity, earlyRenewal uint32) string {
	return fmt.Sprintf(`
        resource "tls_self_signed_cert" "test1" {
            subject {
                common_name = "example.com"
                organization = "Example, Inc"
                organizational_unit = "Department of Terraform Testing"
                street_address = ["5879 Cotton Link"]
                locality = "Pirate Harbor"
                province = "CA"
                country = "US"
                postal_code = "95559-1227"
                serial_number = "2"
            }

            dns_names = [
                "example.com",
                "example.net",
            ]

            ip_addresses = [
                "127.0.0.1",
                "127.0.0.2",
            ]

            uris = [
                "spiffe://example-trust-domain/ca",
                "spiffe://example-trust-domain/ca2",
            ]

            validity_period_hours = %d
            early_renewal_hours = %d

            allowed_uses = [
                "key_encipherment",
                "digital_signature",
                "server_auth",
                "client_auth",
                "non_repudiation",
            ]

            key_algorithm = "RSA"
            private_key_pem = <<EOT
%s
EOT
        }`, validity, earlyRenewal, testPrivateKeyPEM)
}

func TestAccResourceSelfSignedCert_FromED25519PrivateKeyResource(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_self_signed_cert" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						subject {
							organization = "test-organization"
						}
						is_ca_certificate     = true
						validity_period_hours = 8760
						allowed_uses = [
							"cert_signing",
						]
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "ED25519"),
					testCheckPEMFormat("tls_self_signed_cert.test", "cert_pem", PreambleCertificate),
				),
			},
		},
	})
}

func TestAccResourceSelfSignedCert_FromECDSAPrivateKeyResource(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm   = "ECDSA"
						ecdsa_curve = "P521"
					}
					resource "tls_self_signed_cert" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						subject {
							organization = "test-organization"
						}
						is_ca_certificate     = true
						set_subject_key_id    = true
						validity_period_hours = 8760
						allowed_uses = [
							"cert_signing",
						]
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "ECDSA"),
					testCheckPEMFormat("tls_self_signed_cert.test", "cert_pem", PreambleCertificate),
				),
			},
		},
	})
}

func TestAccResourceSelfSignedCert_FromRSAPrivateKeyResource(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
						rsa_bits  = 4096
					}
					resource "tls_self_signed_cert" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						subject {
							organization = "test-organization"
						}
						is_ca_certificate     = true
						set_subject_key_id    = true
						validity_period_hours = 8760
						allowed_uses = [
							"cert_signing",
						]
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "RSA"),
					testCheckPEMFormat("tls_self_signed_cert.test", "cert_pem", PreambleCertificate),
				),
			},
		},
	})
}

func TestAccResourceSelfSignedCert_NoSubject(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_self_signed_cert" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						set_subject_key_id    = true
						validity_period_hours = 8760
						subject {}
						allowed_uses = [
							"key_encipherment",
							"digital_signature",
							"server_auth",
							"client_auth",
							"cert_signing",
						]
						dns_names = [
							"pippo.pluto.paperino",
						]
						ip_addresses = [
							"127.0.0.2",
						]
						uris = [
							"disney://pippo.pluto.paperino/minnie",
						]
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "ED25519"),
					testCheckPEMFormat("tls_self_signed_cert.test", "cert_pem", PreambleCertificate),
					testCheckPEMCertificateNoSubject("tls_self_signed_cert.test", "cert_pem"),
					testCheckPEMCertificateKeyUsage("tls_self_signed_cert.test", "cert_pem", x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature),
					testCheckPEMCertificateExtKeyUsages("tls_self_signed_cert.test", "cert_pem", []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
						x509.ExtKeyUsageClientAuth,
					}),
					testCheckPEMCertificateDNSNames("tls_self_signed_cert.test", "cert_pem", []string{
						"pippo.pluto.paperino",
					}),
					testCheckPEMCertificateIPAddresses("tls_self_signed_cert.test", "cert_pem", []net.IP{
						net.ParseIP("127.0.0.2"),
					}),
					testCheckPEMCertificateURIs("tls_self_signed_cert.test", "cert_pem", []*url.URL{
						{
							Scheme: "disney",
							Host:   "pippo.pluto.paperino",
							Path:   "minnie",
						},
					}),
				),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_self_signed_cert" "test" {
						private_key_pem = tls_private_key.test.private_key_pem
						set_subject_key_id    = true
						validity_period_hours = 8760
						allowed_uses = [
							"key_encipherment",
							"digital_signature",
							"server_auth",
							"client_auth",
							"cert_signing",
						]
						dns_names = [
							"pippo.pluto.paperino",
						]
						ip_addresses = [
							"127.0.0.2",
						]
						uris = [
							"disney://pippo.pluto.paperino/minnie",
						]
					}
				`,
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "ED25519"),
					testCheckPEMFormat("tls_self_signed_cert.test", "cert_pem", PreambleCertificate),
					testCheckPEMCertificateNoSubject("tls_self_signed_cert.test", "cert_pem"),
					testCheckPEMCertificateKeyUsage("tls_self_signed_cert.test", "cert_pem", x509.KeyUsageCertSign|x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature),
					testCheckPEMCertificateExtKeyUsages("tls_self_signed_cert.test", "cert_pem", []x509.ExtKeyUsage{
						x509.ExtKeyUsageServerAuth,
						x509.ExtKeyUsageClientAuth,
					}),
					testCheckPEMCertificateDNSNames("tls_self_signed_cert.test", "cert_pem", []string{
						"pippo.pluto.paperino",
					}),
					testCheckPEMCertificateIPAddresses("tls_self_signed_cert.test", "cert_pem", []net.IP{
						net.ParseIP("127.0.0.2"),
					}),
					testCheckPEMCertificateURIs("tls_self_signed_cert.test", "cert_pem", []*url.URL{
						{
							Scheme: "disney",
							Host:   "pippo.pluto.paperino",
							Path:   "minnie",
						},
					}),
				),
			},
		},
	})
}
