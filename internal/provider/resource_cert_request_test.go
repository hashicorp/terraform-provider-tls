package provider

import (
	"crypto/x509/pkix"
	"net"
	"net/url"
	"regexp"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	tu "github.com/hashicorp/terraform-provider-tls/internal/provider/testutils"
)

func TestAccResourceCertRequest(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test1" {
						algorithm = "ED25519"
					}
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
						private_key_pem = tls_private_key.test1.private_key_pem
					}
                `,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_cert_request.test1", "cert_request_pem", PreambleCertificateRequest.String()),
					tu.TestCheckPEMCertificateRequestSubject("tls_cert_request.test1", "cert_request_pem", &pkix.Name{
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
					tu.TestCheckPEMCertificateRequestDNSNames("tls_cert_request.test1", "cert_request_pem", []string{
						"example.com",
						"example.net",
					}),
					tu.TestCheckPEMCertificateRequestIPAddresses("tls_cert_request.test1", "cert_request_pem", []net.IP{
						net.ParseIP("127.0.0.1"),
						net.ParseIP("127.0.0.2"),
					}),
					tu.TestCheckPEMCertificateRequestURIs("tls_cert_request.test1", "cert_request_pem", []*url.URL{
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
				Config: `
					resource "tls_private_key" "test2" {
						algorithm = "ED25519"
					}
					resource "tls_cert_request" "test2" {
						subject {
							serial_number = "42"
						}
						private_key_pem = tls_private_key.test2.private_key_pem
					}
                `,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_cert_request.test2", "cert_request_pem", PreambleCertificateRequest.String()),
					tu.TestCheckPEMCertificateRequestSubject("tls_cert_request.test2", "cert_request_pem", &pkix.Name{
						SerialNumber: "42",
					}),
					tu.TestCheckPEMCertificateRequestDNSNames("tls_cert_request.test2", "cert_request_pem", []string{}),
					tu.TestCheckPEMCertificateRequestIPAddresses("tls_cert_request.test2", "cert_request_pem", []net.IP{}),
					tu.TestCheckPEMCertificateRequestURIs("tls_cert_request.test2", "cert_request_pem", []*url.URL{}),
				),
			},
		},
	})
}

func TestAccResourceCertRequest_NoSubject(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_cert_request" "test" {
						dns_names = [
							"pippo.pluto.paperino",
						]
						ip_addresses = [
							"127.0.0.2",
						]
						uris = [
							"disney://pippo.pluto.paperino/minnie",
						]
						private_key_pem = tls_private_key.test.private_key_pem
                    }
                `,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_cert_request.test", "cert_request_pem", PreambleCertificateRequest.String()),
					tu.TestCheckPEMCertificateRequestNoSubject("tls_cert_request.test", "cert_request_pem"),
					tu.TestCheckPEMCertificateRequestDNSNames("tls_cert_request.test", "cert_request_pem", []string{
						"pippo.pluto.paperino",
					}),
					tu.TestCheckPEMCertificateRequestIPAddresses("tls_cert_request.test", "cert_request_pem", []net.IP{
						net.ParseIP("127.0.0.2"),
					}),
					tu.TestCheckPEMCertificateRequestURIs("tls_cert_request.test", "cert_request_pem", []*url.URL{
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
					resource "tls_cert_request" "test" {
						subject {}
						dns_names = [
							"pippo.pluto.paperino",
						]
						ip_addresses = [
							"127.0.0.2",
						]
						uris = [
							"disney://pippo.pluto.paperino/minnie",
						]
						private_key_pem = tls_private_key.test.private_key_pem
                    }
                `,
				Check: r.ComposeAggregateTestCheckFunc(
					tu.TestCheckPEMFormat("tls_cert_request.test", "cert_request_pem", PreambleCertificateRequest.String()),
					tu.TestCheckPEMCertificateRequestNoSubject("tls_cert_request.test", "cert_request_pem"),
					tu.TestCheckPEMCertificateRequestDNSNames("tls_cert_request.test", "cert_request_pem", []string{
						"pippo.pluto.paperino",
					}),
					tu.TestCheckPEMCertificateRequestIPAddresses("tls_cert_request.test", "cert_request_pem", []net.IP{
						net.ParseIP("127.0.0.2"),
					}),
					tu.TestCheckPEMCertificateRequestURIs("tls_cert_request.test", "cert_request_pem", []*url.URL{
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

func TestAccResourceCertRequest_InvalidConfigs(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),
		Steps: []r.TestStep{
			{
				Config: `
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
					resource "tls_cert_request" "test" {
						subject {}
						subject {}
						dns_names = [
							"pippo.pluto.paperino",
						]
						ip_addresses = [
							"127.0.0.2",
						]
						uris = [
							"disney://pippo.pluto.paperino/minnie",
						]
						private_key_pem = tls_private_key.test.private_key_pem
                    }
                `,
				ExpectError: regexp.MustCompile("Too many (list items|subject blocks)"),
			},
		},
	})
}
