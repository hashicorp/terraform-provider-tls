package provider

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"regexp"
	"testing"
	"time"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestSelfSignedCert(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: selfSignedCertConfig(1, 0),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestMatchResourceAttr("tls_self_signed_cert.test1", "cert_pem", regexp.MustCompile(`^-----BEGIN CERTIFICATE----`)),
					r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
						block, _ := pem.Decode([]byte(value))
						cert, err := x509.ParseCertificate(block.Bytes)
						if err != nil {
							return fmt.Errorf("error parsing cert: %s", err)
						}
						if expected, got := "2", cert.Subject.SerialNumber; got != expected {
							return fmt.Errorf("incorrect subject serial number: expected %v, got %v", expected, got)
						}
						if expected, got := "example.com", cert.Subject.CommonName; got != expected {
							return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
						}
						if expected, got := "Example, Inc", cert.Subject.Organization[0]; got != expected {
							return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected, got)
						}
						if expected, got := "Department of Terraform Testing", cert.Subject.OrganizationalUnit[0]; got != expected {
							return fmt.Errorf("incorrect subject organizational unit: expected %v, got %v", expected, got)
						}
						if expected, got := "5879 Cotton Link", cert.Subject.StreetAddress[0]; got != expected {
							return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
						}
						if expected, got := "Pirate Harbor", cert.Subject.Locality[0]; got != expected {
							return fmt.Errorf("incorrect subject locality: expected %v, got %v", expected, got)
						}
						if expected, got := "CA", cert.Subject.Province[0]; got != expected {
							return fmt.Errorf("incorrect subject province: expected %v, got %v", expected, got)
						}
						if expected, got := "US", cert.Subject.Country[0]; got != expected {
							return fmt.Errorf("incorrect subject country: expected %v, got %v", expected, got)
						}
						if expected, got := "95559-1227", cert.Subject.PostalCode[0]; got != expected {
							return fmt.Errorf("incorrect subject postal code: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.DNSNames); got != expected {
							return fmt.Errorf("incorrect number of DNS names: expected %v, got %v", expected, got)
						}
						if expected, got := "example.com", cert.DNSNames[0]; got != expected {
							return fmt.Errorf("incorrect DNS name 0: expected %v, got %v", expected, got)
						}
						if expected, got := "example.net", cert.DNSNames[1]; got != expected {
							return fmt.Errorf("incorrect DNS name 0: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.IPAddresses); got != expected {
							return fmt.Errorf("incorrect number of IP addresses: expected %v, got %v", expected, got)
						}
						if expected, got := "127.0.0.1", cert.IPAddresses[0].String(); got != expected {
							return fmt.Errorf("incorrect IP address 0: expected %v, got %v", expected, got)
						}
						if expected, got := "127.0.0.2", cert.IPAddresses[1].String(); got != expected {
							return fmt.Errorf("incorrect IP address 0: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.URIs); got != expected {
							return fmt.Errorf("incorrect number of URIs: expected %v, got %v", expected, got)
						}
						if expected, got := "spiffe://example-trust-domain/ca", cert.URIs[0].String(); got != expected {
							return fmt.Errorf("incorrect URI 0: expected %v, got %v", expected, got)
						}
						if expected, got := "spiffe://example-trust-domain/ca2", cert.URIs[1].String(); got != expected {
							return fmt.Errorf("incorrect URI 1: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.ExtKeyUsage); got != expected {
							return fmt.Errorf("incorrect number of ExtKeyUsage: expected %v, got %v", expected, got)
						}
						if expected, got := x509.ExtKeyUsageServerAuth, cert.ExtKeyUsage[0]; got != expected {
							return fmt.Errorf("incorrect ExtKeyUsage[0]: expected %v, got %v", expected, got)
						}
						if expected, got := x509.ExtKeyUsageClientAuth, cert.ExtKeyUsage[1]; got != expected {
							return fmt.Errorf("incorrect ExtKeyUsage[1]: expected %v, got %v", expected, got)
						}

						if expected, got := x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, cert.KeyUsage; got != expected {
							return fmt.Errorf("incorrect KeyUsage: expected %v, got %v", expected, got)
						}

						// This time checking is a bit sloppy to avoid inconsistent test results
						// depending on the power of the machine running the tests.
						now := time.Now()
						if cert.NotBefore.After(now) {
							return fmt.Errorf("certificate validity begins in the future")
						}
						if now.Sub(cert.NotBefore) > (2 * time.Minute) {
							return fmt.Errorf("certificate validity begins more than two minutes in the past")
						}
						if cert.NotAfter.Sub(cert.NotBefore) != time.Hour {
							return fmt.Errorf("certificate validity is not one hour")
						}

						return nil
					}),
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
					r.TestMatchResourceAttr("tls_self_signed_cert.test2", "cert_pem", regexp.MustCompile(`^-----BEGIN CERTIFICATE----`)),
					r.TestCheckResourceAttrWith("tls_self_signed_cert.test2", "cert_pem", func(value string) error {
						block, _ := pem.Decode([]byte(value))
						cert, err := x509.ParseCertificate(block.Bytes)
						if err != nil {
							return fmt.Errorf("error parsing cert: %s", err)
						}
						if expected, got := "42", cert.Subject.SerialNumber; got != expected {
							return fmt.Errorf("incorrect subject serial number: expected %v, got %v", expected, got)
						}
						if expected, got := "", cert.Subject.CommonName; got != expected {
							return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
						}
						if expected, got := 0, len(cert.Subject.Organization); got != expected {
							return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected, got)
						}
						if expected, got := 0, len(cert.Subject.OrganizationalUnit); got != expected {
							return fmt.Errorf("incorrect subject organizational unit: expected %v, got %v", expected, got)
						}
						if expected, got := 0, len(cert.Subject.StreetAddress); got != expected {
							return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
						}
						if expected, got := 0, len(cert.Subject.Locality); got != expected {
							return fmt.Errorf("incorrect subject locality: expected %v, got %v", expected, got)
						}
						if expected, got := 0, len(cert.Subject.Province); got != expected {
							return fmt.Errorf("incorrect subject province: expected %v, got %v", expected, got)
						}
						if expected, got := 0, len(cert.Subject.Country); got != expected {
							return fmt.Errorf("incorrect subject country: expected %v, got %v", expected, got)
						}
						if expected, got := 0, len(cert.Subject.PostalCode); got != expected {
							return fmt.Errorf("incorrect subject postal code: expected %v, got %v", expected, got)
						}

						if expected, got := 0, len(cert.DNSNames); got != expected {
							return fmt.Errorf("incorrect number of DNS names: expected %v, got %v", expected, got)
						}

						if expected, got := 0, len(cert.IPAddresses); got != expected {
							return fmt.Errorf("incorrect number of IP addresses: expected %v, got %v", expected, got)
						}

						if expected, got := 0, len(cert.ExtKeyUsage); got != expected {
							return fmt.Errorf("incorrect number of ExtKeyUsage: expected %v, got %v", expected, got)
						}
						if expected, got := []byte(``), cert.SubjectKeyId; !bytes.Equal(got, expected) {
							return fmt.Errorf("incorrect subject key id: expected %v, got %v", expected, got)
						}

						if expected, got := x509.KeyUsage(0), cert.KeyUsage; got != expected {
							return fmt.Errorf("incorrect KeyUsage: expected %v, got %v", expected, got)
						}

						return nil
					}),
				),
			},
		},
	})
}

// TODO Remove this as part of https://github.com/hashicorp/terraform-provider-tls/issues/174
func TestSelfSignedCert_HandleKeyAlgorithmDeprecation(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: selfSignedCertConfigWithDeprecatedKeyAlgorithm(1, 0),
				Check: r.ComposeAggregateTestCheckFunc(
					r.TestMatchResourceAttr("tls_self_signed_cert.test1", "cert_pem", regexp.MustCompile(`^-----BEGIN CERTIFICATE----`)),
					r.TestCheckResourceAttrWith("tls_self_signed_cert.test1", "cert_pem", func(value string) error {
						block, _ := pem.Decode([]byte(value))
						cert, err := x509.ParseCertificate(block.Bytes)
						if err != nil {
							return fmt.Errorf("error parsing cert: %s", err)
						}
						if expected, got := "2", cert.Subject.SerialNumber; got != expected {
							return fmt.Errorf("incorrect subject serial number: expected %v, got %v", expected, got)
						}
						if expected, got := "example.com", cert.Subject.CommonName; got != expected {
							return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
						}
						if expected, got := "Example, Inc", cert.Subject.Organization[0]; got != expected {
							return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected, got)
						}
						if expected, got := "Department of Terraform Testing", cert.Subject.OrganizationalUnit[0]; got != expected {
							return fmt.Errorf("incorrect subject organizational unit: expected %v, got %v", expected, got)
						}
						if expected, got := "5879 Cotton Link", cert.Subject.StreetAddress[0]; got != expected {
							return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
						}
						if expected, got := "Pirate Harbor", cert.Subject.Locality[0]; got != expected {
							return fmt.Errorf("incorrect subject locality: expected %v, got %v", expected, got)
						}
						if expected, got := "CA", cert.Subject.Province[0]; got != expected {
							return fmt.Errorf("incorrect subject province: expected %v, got %v", expected, got)
						}
						if expected, got := "US", cert.Subject.Country[0]; got != expected {
							return fmt.Errorf("incorrect subject country: expected %v, got %v", expected, got)
						}
						if expected, got := "95559-1227", cert.Subject.PostalCode[0]; got != expected {
							return fmt.Errorf("incorrect subject postal code: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.DNSNames); got != expected {
							return fmt.Errorf("incorrect number of DNS names: expected %v, got %v", expected, got)
						}
						if expected, got := "example.com", cert.DNSNames[0]; got != expected {
							return fmt.Errorf("incorrect DNS name 0: expected %v, got %v", expected, got)
						}
						if expected, got := "example.net", cert.DNSNames[1]; got != expected {
							return fmt.Errorf("incorrect DNS name 0: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.IPAddresses); got != expected {
							return fmt.Errorf("incorrect number of IP addresses: expected %v, got %v", expected, got)
						}
						if expected, got := "127.0.0.1", cert.IPAddresses[0].String(); got != expected {
							return fmt.Errorf("incorrect IP address 0: expected %v, got %v", expected, got)
						}
						if expected, got := "127.0.0.2", cert.IPAddresses[1].String(); got != expected {
							return fmt.Errorf("incorrect IP address 0: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.URIs); got != expected {
							return fmt.Errorf("incorrect number of URIs: expected %v, got %v", expected, got)
						}
						if expected, got := "spiffe://example-trust-domain/ca", cert.URIs[0].String(); got != expected {
							return fmt.Errorf("incorrect URI 0: expected %v, got %v", expected, got)
						}
						if expected, got := "spiffe://example-trust-domain/ca2", cert.URIs[1].String(); got != expected {
							return fmt.Errorf("incorrect URI 1: expected %v, got %v", expected, got)
						}

						if expected, got := 2, len(cert.ExtKeyUsage); got != expected {
							return fmt.Errorf("incorrect number of ExtKeyUsage: expected %v, got %v", expected, got)
						}
						if expected, got := x509.ExtKeyUsageServerAuth, cert.ExtKeyUsage[0]; got != expected {
							return fmt.Errorf("incorrect ExtKeyUsage[0]: expected %v, got %v", expected, got)
						}
						if expected, got := x509.ExtKeyUsageClientAuth, cert.ExtKeyUsage[1]; got != expected {
							return fmt.Errorf("incorrect ExtKeyUsage[1]: expected %v, got %v", expected, got)
						}

						if expected, got := x509.KeyUsageKeyEncipherment|x509.KeyUsageDigitalSignature, cert.KeyUsage; got != expected {
							return fmt.Errorf("incorrect KeyUsage: expected %v, got %v", expected, got)
						}

						// This time checking is a bit sloppy to avoid inconsistent test results
						// depending on the power of the machine running the tests.
						now := time.Now()
						if cert.NotBefore.After(now) {
							return fmt.Errorf("certificate validity begins in the future")
						}
						if now.Sub(cert.NotBefore) > (2 * time.Minute) {
							return fmt.Errorf("certificate validity begins more than two minutes in the past")
						}
						if cert.NotAfter.Sub(cert.NotBefore) != time.Hour {
							return fmt.Errorf("certificate validity is not one hour")
						}

						return nil
					}),
				),
			},
		},
	})
}

func TestAccSelfSignedCertRecreatesAfterExpired(t *testing.T) {
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

func TestAccSelfSignedCertNotRecreatedForEarlyRenewalUpdateInFuture(t *testing.T) {
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

func TestAccSelfSignedCertSetSubjectKeyID(t *testing.T) {
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
				Check: r.TestCheckResourceAttrWith("tls_self_signed_cert.test", "cert_pem", func(value string) error {
					block, _ := pem.Decode([]byte(value))
					cert, err := x509.ParseCertificate(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing cert: %s", err)
					}
					got := cert.SubjectKeyId
					want := []byte{207, 81, 38, 63, 172, 18, 241, 109, 195, 169, 6, 109, 237, 6, 18, 214, 52, 231, 17, 222}
					if !bytes.Equal(got, want) {
						return fmt.Errorf("incorrect subject key id\ngot:  %v\nwant: %v", got, want)
					}
					return nil
				}),
			},
		},
	})
}

func TestAccSelfSignedCert_InvalidConfigs(t *testing.T) {
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
				Check: r.ComposeTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "ED25519"),
					r.TestMatchResourceAttr("tls_self_signed_cert.test", "cert_pem", regexp.MustCompile(`-----BEGIN CERTIFICATE-----((.|\n)+?)-----END CERTIFICATE-----`)),
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
				Check: r.ComposeTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "ECDSA"),
					r.TestMatchResourceAttr("tls_self_signed_cert.test", "cert_pem", regexp.MustCompile(`-----BEGIN CERTIFICATE-----((.|\n)+?)-----END CERTIFICATE-----`)),
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
				Check: r.ComposeTestCheckFunc(
					r.TestCheckResourceAttr("tls_self_signed_cert.test", "key_algorithm", "RSA"),
					r.TestMatchResourceAttr("tls_self_signed_cert.test", "cert_pem", regexp.MustCompile(`-----BEGIN CERTIFICATE-----((.|\n)+?)-----END CERTIFICATE-----`)),
				),
			},
		},
	})
}
