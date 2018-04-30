package tls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestCertRequest(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			// Test deprecated form of subject with string values
			r.TestStep{
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

                        key_algorithm = "RSA"
                        private_key_pem = <<EOT
%s
EOT
                    }
                    output "key_pem_1" {
                        value = "${tls_cert_request.test1.cert_request_pem}"
                    }
                `, testPrivateKey),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["key_pem_1"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_1\" is not a string")
					}
					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE REQUEST----") {
						return fmt.Errorf("key is missing CSR PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					csr, err := x509.ParseCertificateRequest(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing CSR: %s", err)
					}
					if expected, got := "2", csr.Subject.SerialNumber; got != expected {
						return fmt.Errorf("incorrect subject serial number: expected %v, got %v", expected, got)
					}
					if expected, got := "example.com", csr.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}
					if expected, got := "Example, Inc", csr.Subject.Organization[0]; got != expected {
						return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected, got)
					}
					if expected, got := "Department of Terraform Testing", csr.Subject.OrganizationalUnit[0]; got != expected {
						return fmt.Errorf("incorrect subject organizational unit: expected %v, got %v", expected, got)
					}
					if expected, got := "5879 Cotton Link", csr.Subject.StreetAddress[0]; got != expected {
						return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
					}
					if expected, got := "Pirate Harbor", csr.Subject.Locality[0]; got != expected {
						return fmt.Errorf("incorrect subject locality: expected %v, got %v", expected, got)
					}
					if expected, got := "CA", csr.Subject.Province[0]; got != expected {
						return fmt.Errorf("incorrect subject province: expected %v, got %v", expected, got)
					}
					if expected, got := "US", csr.Subject.Country[0]; got != expected {
						return fmt.Errorf("incorrect subject country: expected %v, got %v", expected, got)
					}
					if expected, got := "95559-1227", csr.Subject.PostalCode[0]; got != expected {
						return fmt.Errorf("incorrect subject postal code: expected %v, got %v", expected, got)
					}
					if expected, got := 2, len(csr.DNSNames); got != expected {
						return fmt.Errorf("incorrect number of DNS names: expected %v, got %v", expected, got)
					}
					if expected, got := "example.com", csr.DNSNames[0]; got != expected {
						return fmt.Errorf("incorrect DNS name 0: expected %v, got %v", expected, got)
					}
					if expected, got := "example.net", csr.DNSNames[1]; got != expected {
						return fmt.Errorf("incorrect DNS name 1: expected %v, got %v", expected, got)
					}
					if expected, got := 2, len(csr.IPAddresses); got != expected {
						return fmt.Errorf("incorrect number of IP addresses: expected %v, got %v", expected, got)
					}
					if expected, got := "127.0.0.1", csr.IPAddresses[0].String(); got != expected {
						return fmt.Errorf("incorrect IP address 0: expected %v, got %v", expected, got)
					}
					if expected, got := "127.0.0.2", csr.IPAddresses[1].String(); got != expected {
						return fmt.Errorf("incorrect IP address 1: expected %v, got %v", expected, got)
					}

					return nil
				},
			},
			// Test that default subject values are go zero values. However subject field cannot be completely empty,
			// so we need two tests to cover all the cases.
			r.TestStep{
				Config: fmt.Sprintf(`
                   resource "tls_cert_request" "test2a" {
                       subject {
							serial_number = "42"
						}

                       key_algorithm = "RSA"
                       private_key_pem = <<EOT
%s
EOT
                   }
                   output "key_pem_2a" {
                       value = "${tls_cert_request.test2a.cert_request_pem}"
                   }
				`, testPrivateKey),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["key_pem_2a"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_2a\" is not a string")
					}
					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE REQUEST----") {
						return fmt.Errorf("key is missing CSR PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					csr, err := x509.ParseCertificateRequest(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing CSR: %s", err)
					}
					if expected, got := "42", csr.Subject.SerialNumber; got != expected {
						return fmt.Errorf("incorrect subject serial number: expected %v, got %v", expected, got)
					}
					if expected, got := "", csr.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}
					if got := csr.Subject.Organization; got != nil {
						return fmt.Errorf("incorrect subject organization: expected nil, got %v", got)
					}
					if got := csr.Subject.OrganizationalUnit; got != nil {
						return fmt.Errorf("incorrect subject organizational unit: expected nil, got %v", got)
					}
					if got := csr.Subject.StreetAddress; got != nil {
						return fmt.Errorf("incorrect subject street address: expected nil, got %v", got)
					}
					if got := csr.Subject.Locality; got != nil {
						return fmt.Errorf("incorrect subject locality: expected nil, got %v", got)
					}
					if got := csr.Subject.Province; got != nil {
						return fmt.Errorf("incorrect subject province: expected nil, got %v", got)
					}
					if got := csr.Subject.Country; got != nil {
						return fmt.Errorf("incorrect subject country: expected nil, got %v", got)
					}
					if got := csr.Subject.PostalCode; got != nil {
						return fmt.Errorf("incorrect subject postal code: expected nil, got %v", got)
					}
					if got := csr.DNSNames; got != nil {
						return fmt.Errorf("incorrect list of DNS names: expected nil, got %v", got)
					}
					if got := csr.IPAddresses; got != nil {
						return fmt.Errorf("incorrect list of IP addresses: expected nil, got %v", got)
					}

					return nil
				},
			},
			r.TestStep{
				Config: fmt.Sprintf(`
                   resource "tls_cert_request" "test2b" {
                       subject {
							common_name = "forty-two"
						}

                       key_algorithm = "RSA"
                       private_key_pem = <<EOT
%s
EOT
                   }
                   output "key_pem_2b" {
                       value = "${tls_cert_request.test2b.cert_request_pem}"
                   }
				`, testPrivateKey),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["key_pem_2b"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_2b\" is not a string")
					}
					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE REQUEST----") {
						return fmt.Errorf("key is missing CSR PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					csr, err := x509.ParseCertificateRequest(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing CSR: %s", err)
					}
					if expected, got := "forty-two", csr.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}

					return nil
				},
			},
			// Test list of strings attributes
			r.TestStep{
				Config: fmt.Sprintf(`
                   resource "tls_cert_request" "test3a" {
                       subject {
							serial_number = "43"
							common_name = "hey ho"
							organization = ["Testy", "McTesterFace"]
							organizational_unit = ["Unit test"]
							street_address = ["123 Drury Lane", "Nowhere", "Montana"]
							locality = ["USA"]
							province = ["Provincial"]
							country = ["Candy Mountain"]
							postal_code = ["78739"]
						}

                       key_algorithm = "RSA"
                       private_key_pem = <<EOT
%s
EOT
                   }
                   output "key_pem_3a" {
                       value = "${tls_cert_request.test3a.cert_request_pem}"
                   }
				`, testPrivateKey),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["key_pem_3a"].Value

					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"key_pem_3a\" is not a string")
					}
					if !strings.HasPrefix(got, "-----BEGIN CERTIFICATE REQUEST----") {
						return fmt.Errorf("key is missing CSR PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					csr, err := x509.ParseCertificateRequest(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing CSR: %s", err)
					}
					if expected, got := "43", csr.Subject.SerialNumber; got != expected {
						return fmt.Errorf("incorrect subject serial number: expected %v, got %v", expected, got)
					}
					if expected, got := "hey ho", csr.Subject.CommonName; got != expected {
						return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected, got)
					}
					if expected, got := 2, len(csr.Subject.Organization); got != expected {
						return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected, got)
					}
					if expected, got := "Testy", csr.Subject.Organization[0]; got != expected {
						return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected, got)
					}
					if expected, got := "McTesterFace", csr.Subject.Organization[1]; got != expected {
						return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected, got)
					}
					if expected, got := 1, len(csr.Subject.OrganizationalUnit); got != expected {
						return fmt.Errorf("incorrect subject organization_unit: expected %v, got %v", expected, got)
					}
					if expected, got := "Unit test", csr.Subject.OrganizationalUnit[0]; got != expected {
						return fmt.Errorf("incorrect subject organizational unit: expected %v, got %v", expected, got)
					}
					if expected, got := 3, len(csr.Subject.StreetAddress); got != expected {
						return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
					}
					if expected, got := "123 Drury Lane", csr.Subject.StreetAddress[0]; got != expected {
						return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
					}
					if expected, got := "Nowhere", csr.Subject.StreetAddress[1]; got != expected {
						return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
					}
					if expected, got := "Montana", csr.Subject.StreetAddress[2]; got != expected {
						return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected, got)
					}
					if expected, got := 1, len(csr.Subject.Locality); got != expected {
						return fmt.Errorf("incorrect subject locality: expected %v, got %v", expected, got)
					}
					if expected, got := "USA", csr.Subject.Locality[0]; got != expected {
						return fmt.Errorf("incorrect subject locality: expected %v, got %v", expected, got)
					}
					if expected, got := 1, len(csr.Subject.Province); got != expected {
						return fmt.Errorf("incorrect subject province: expected %v, got %v", expected, got)
					}
					if expected, got := "Provincial", csr.Subject.Province[0]; got != expected {
						return fmt.Errorf("incorrect subject province: expected %v, got %v", expected, got)
					}
					if expected, got := 1, len(csr.Subject.Country); got != expected {
						return fmt.Errorf("incorrect subject country: expected %v, got %v", expected, got)
					}
					if expected, got := "Candy Mountain", csr.Subject.Country[0]; got != expected {
						return fmt.Errorf("incorrect subject country: expected %v, got %v", expected, got)
					}
					if expected, got := 1, len(csr.Subject.PostalCode); got != expected {
						return fmt.Errorf("incorrect subject postal code: expected %v, got %v", expected, got)
					}
					if expected, got := "78739", csr.Subject.PostalCode[0]; got != expected {
						return fmt.Errorf("incorrect subject postal code: expected %v, got %v", expected, got)
					}
					if got := csr.DNSNames; got != nil {
						return fmt.Errorf("incorrect list of DNS names: expected nil, got %v", got)
					}
					if got := csr.IPAddresses; got != nil {
						return fmt.Errorf("incorrect list of IP addresses: expected nil, got %v", got)
					}

					return nil
				},
			},
		},
	})
}
