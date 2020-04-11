package tls

import (
	"crypto/x509"
	"encoding/pem"

	"fmt"
	"strings"
	"testing"

	r "github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
)

func TestCRL(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: certRevocationListConfig(1, 0),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}
					if !strings.HasPrefix(got, "-----BEGIN X509 CRL----") {
						return fmt.Errorf("key is missing CRL PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					crl, err := x509.ParseCRL(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing crl: %s", err)
					}

					// Verify CRL signature with CA.
					caCert, err := decodeCertificateFromBytes([]byte(testCACert))
					if err != nil {
						return fmt.Errorf("error parsing ca cert: %s", err)
					}
					err = caCert.CheckCRLSignature(crl)
					if err != nil {
						return fmt.Errorf("Wrong CRL signature %s", err)
					}
					if caCert.SerialNumber.Cmp(crl.TBSCertList.RevokedCertificates[0].SerialNumber) != 0 {
						return fmt.Errorf("revoked certificate serial number doesn't match")
					}
					return nil
				},
			},
		},
	})
}

func TestCRLEmptyListOfRevokedCerts(t *testing.T) {
	r.UnitTest(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			{
				Config: certRevocationListEmptyConfig(1, 0),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}
					if !strings.HasPrefix(got, "-----BEGIN X509 CRL----") {
						return fmt.Errorf("key is missing cert PEM preamble")
					}
					block, _ := pem.Decode([]byte(got))
					crl, err := x509.ParseCRL(block.Bytes)
					if err != nil {
						return fmt.Errorf("error parsing crl: %s", err)
					}

					// Verify list of revoked certificates is empty.
					if len(crl.TBSCertList.RevokedCertificates) != 0 {
						return fmt.Errorf("CRL list of revoked certificates must be empty")
					}

					// Verify CRL signature with CA.
					caCert, err := decodeCertificateFromBytes([]byte(testCACert))
					if err != nil {
						return fmt.Errorf("error parsing ca cert: %s", err)
					}
					err = caCert.CheckCRLSignature(crl)
					if err != nil {
						return fmt.Errorf("Wrong CRL signature %s", err)
					}
					return nil
				},
			},
		},
	})
}

func TestAccX509CrlRecreatesAfterExpired(t *testing.T) {
	oldNow := now
	var previousCrl string
	r.UnitTest(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  setTimeForTest("2019-06-14T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: certRevocationListConfig(10, 2),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}
					previousCrl = got
					return nil
				},
			},
			{
				Config: certRevocationListConfig(10, 2),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}

					if got != previousCrl {
						return fmt.Errorf("crl updated even though no time has passed")
					}

					previousCrl = got
					return nil
				},
			},
			{
				PreConfig: setTimeForTest("2019-06-14T19:00:00Z"),
				Config:    certRevocationListConfig(10, 2),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}

					if got != previousCrl {
						return fmt.Errorf("crl updated even though not enough time has passed")
					}

					previousCrl = got
					return nil
				},
			},
			{
				PreConfig: setTimeForTest("2019-06-14T21:00:00Z"),
				Config:    certRevocationListConfig(10, 2),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}

					if got == previousCrl {
						return fmt.Errorf("crl not updated even though passed early renewal")
					}

					previousCrl = got
					return nil
				},
			},
		},
	})
	now = oldNow
}

func TestAccX509CrlNotRecreatedForEarlyRenewalUpdateInFuture(t *testing.T) {
	oldNow := now
	var previousCrl string
	r.UnitTest(t, r.TestCase{
		Providers: testProviders,
		PreCheck:  setTimeForTest("2019-06-14T12:00:00Z"),
		Steps: []r.TestStep{
			{
				Config: certRevocationListConfig(10, 2),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}
					previousCrl = got
					return nil
				},
			},
			{
				Config: certRevocationListConfig(10, 3),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}

					if got != previousCrl {
						return fmt.Errorf("crl updated even though still time until early renewal")
					}

					previousCrl = got
					return nil
				},
			},
			{
				PreConfig: setTimeForTest("2019-06-14T16:00:00Z"),
				Config:    certRevocationListConfig(10, 3),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}

					if got != previousCrl {
						return fmt.Errorf("crl updated even though still time until early renewal")
					}

					previousCrl = got
					return nil
				},
			},
			{
				PreConfig: setTimeForTest("2019-06-14T16:00:00Z"),
				Config:    certRevocationListConfig(10, 9),
				Check: func(s *terraform.State) error {
					gotUntyped := s.RootModule().Outputs["crl_pem"].Value
					got, ok := gotUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"crl_pem\" is not a string")
					}

					if got == previousCrl {
						return fmt.Errorf("crl not updated even though early renewal time has passed")
					}

					previousCrl = got
					return nil
				},
			},
		},
	})
	now = oldNow
}

func certRevocationListConfig(validity uint32, earlyRenewal uint32) string {
	return fmt.Sprintf(`
                    locals {
                         cert_to_revoke = <<EOT
%s
EOT
                    }
                    resource "tls_x509_crl" "test" {
                        certs_to_revoke = [local.cert_to_revoke]

                        validity_period_hours = %d
                        early_renewal_hours = %d

                        ca_cert_pem = <<EOT
%s
EOT
                        ca_key_algorithm = "RSA"
                        ca_private_key_pem = <<EOT
%s
EOT
                    }
                    output "crl_pem" {
                        value = "${tls_x509_crl.test.crl_pem}"
                    }
                `, testCACert, validity, earlyRenewal, testCACert, testCAPrivateKey)
}

func certRevocationListEmptyConfig(validity uint32, earlyRenewal uint32) string {
	return fmt.Sprintf(`
                    resource "tls_x509_crl" "test" {
                        certs_to_revoke = []

                        validity_period_hours = %d
                        early_renewal_hours = %d

                        ca_cert_pem = <<EOT
%s
EOT
                        ca_key_algorithm = "RSA"
                        ca_private_key_pem = <<EOT
%s
EOT
                    }
                    output "crl_pem" {
                        value = "${tls_x509_crl.test.crl_pem}"
                    }
                `, validity, earlyRenewal, testCACert, testCAPrivateKey)
}
