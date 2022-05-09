package provider

import (
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/url"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func TestCertRequest(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: fmt.Sprintf(`
                    resource "tls_cert_request" "test1" {
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
                            "spiffe://example-trust-domain/workload",
                            "spiffe://example-trust-domain/workload2",
                        ]

                        private_key_pem = <<EOT
%s
EOT
                    }
                `, testPrivateKeyPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMFormat("tls_cert_request.test1", "cert_request_pem", PreambleCertificateRequest),
					testCheckPEMCertificateRequestSubject("tls_cert_request.test1", "cert_request_pem", &pkix.Name{
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
					testCheckPEMCertificateRequestDNSNames("tls_cert_request.test1", "cert_request_pem", []string{
						"example.com",
						"example.net",
					}),
					testCheckPEMCertificateRequestIPAddresses("tls_cert_request.test1", "cert_request_pem", []net.IP{
						net.ParseIP("127.0.0.1"),
						net.ParseIP("127.0.0.2"),
					}),
					testCheckPEMCertificateRequestURIs("tls_cert_request.test1", "cert_request_pem", []*url.URL{
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
				),
			},
			{
				Config: fmt.Sprintf(`
                    resource "tls_cert_request" "test2" {
                        subject {
						serial_number = "42"
						}

                        private_key_pem = <<EOT
%s
EOT
                    }
                `, testPrivateKeyPEM),
				Check: r.ComposeAggregateTestCheckFunc(
					testCheckPEMFormat("tls_cert_request.test2", "cert_request_pem", PreambleCertificateRequest),
					testCheckPEMCertificateRequestSubject("tls_cert_request.test2", "cert_request_pem", &pkix.Name{
						SerialNumber: "42",
					}),
					testCheckPEMCertificateRequestDNSNames("tls_cert_request.test2", "cert_request_pem", []string{}),
					testCheckPEMCertificateRequestIPAddresses("tls_cert_request.test2", "cert_request_pem", []net.IP{}),
					testCheckPEMCertificateRequestURIs("tls_cert_request.test2", "cert_request_pem", []*url.URL{}),
				),
			},
		},
	})
}

// TODO Remove this as part of https://github.com/hashicorp/terraform-provider-tls/issues/174
func TestCertRequest_HandleKeyAlgorithmDeprecation(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProviderFactories: testProviders,
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					resource "tls_cert_request" "test" {
						subject {
							serial_number = "42"
						}
						key_algorithm = "RSA"
						private_key_pem = tls_private_key.test.private_key_pem
					}
				`,
				Check: r.TestCheckResourceAttr("tls_cert_request.test", "key_algorithm", "RSA"),
			},
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "RSA"
					}
					resource "tls_cert_request" "test" {
						subject {
							serial_number = "42"
						}
						private_key_pem = tls_private_key.test.private_key_pem
					}
				`,
				Check: r.TestCheckResourceAttr("tls_cert_request.test", "key_algorithm", "RSA"),
			},
		},
	},
	)
}
