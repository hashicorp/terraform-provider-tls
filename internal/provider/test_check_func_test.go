package provider

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"time"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func testCheckPEMFormat(name, key string, expected PEMPreamble) r.TestCheckFunc {
	return r.TestMatchResourceAttr(name, key, regexp.MustCompile(fmt.Sprintf(`^-----BEGIN %[1]s-----\n(.|\s)+\n-----END %[1]s-----\n$`, expected)))
}

func testCheckPEMCertificateRequestWith(name, key string, f func(csr *x509.CertificateRequest) error) r.TestCheckFunc {
	return r.TestCheckResourceAttrWith(name, key, func(value string) error {
		block, _ := pem.Decode([]byte(value))
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing Certificate Request: %s", err)
		}

		return f(csr)
	})
}

func testCheckPEMCertificateRequestSubject(name, key string, expected *pkix.Name) r.TestCheckFunc {
	return testCheckPEMCertificateRequestWith(name, key, func(csr *x509.CertificateRequest) error {
		return compareCertSubjects(expected, &csr.Subject)
	})
}

//nolint:unparam // `key` parameter always receives `cert_request_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateRequestDNSNames(name, key string, expected []string) r.TestCheckFunc {
	return testCheckPEMCertificateRequestWith(name, key, func(csr *x509.CertificateRequest) error {
		return compareCertDNSNames(expected, csr.DNSNames)
	})
}

//nolint:unparam // `key` parameter always receives `cert_request_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateRequestIPAddresses(name, key string, expected []net.IP) r.TestCheckFunc {
	return testCheckPEMCertificateRequestWith(name, key, func(csr *x509.CertificateRequest) error {
		return compareCertIPAddresses(expected, csr.IPAddresses)
	})
}

//nolint:unparam // `key` parameter always receives `cert_request_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateRequestURIs(name, key string, expected []*url.URL) r.TestCheckFunc {
	return testCheckPEMCertificateRequestWith(name, key, func(csr *x509.CertificateRequest) error {
		return compareCertURIs(expected, csr.URIs)
	})
}

func testCheckPEMCertificateWith(name, key string, f func(csr *x509.Certificate) error) r.TestCheckFunc {
	return r.TestCheckResourceAttrWith(name, key, func(value string) error {
		block, _ := pem.Decode([]byte(value))
		crt, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing Certificate: %s", err)
		}

		return f(crt)
	})
}

//nolint:unparam // `key` parameter always receives `cert_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateSubject(name, key string, expected *pkix.Name) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(crt *x509.Certificate) error {
		return compareCertSubjects(expected, &crt.Subject)
	})
}

//nolint:unparam // `key` parameter always receives `cert_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateDNSNames(name, key string, expected []string) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(crt *x509.Certificate) error {
		return compareCertDNSNames(expected, crt.DNSNames)
	})
}

//nolint:unparam // `key` parameter always receives `cert_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateIPAddresses(name, key string, expected []net.IP) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(crt *x509.Certificate) error {
		return compareCertIPAddresses(expected, crt.IPAddresses)
	})
}

//nolint:unparam // `key` parameter always receives `cert_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateURIs(name, key string, expected []*url.URL) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(crt *x509.Certificate) error {
		return compareCertURIs(expected, crt.URIs)
	})
}

//nolint:unparam // `key` parameter always receives `cert_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateKeyUsage(name, key string, expected x509.KeyUsage) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(crt *x509.Certificate) error {
		if expected != crt.KeyUsage {
			return fmt.Errorf("incorrect Key Usage: expected %v, got %v", expected, crt.KeyUsage)
		}
		return nil
	})
}

//nolint:unparam // `key` parameter always receives `cert_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateExtKeyUsages(name, key string, expected []x509.ExtKeyUsage) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(crt *x509.Certificate) error {
		return compareExtKeyUsages(expected, crt.ExtKeyUsage)
	})
}

//nolint:unparam // `key` parameter always receives `cert_pem` because generated PEMs attributes are called that way.
func testCheckPEMCertificateDuration(name, key string, expected time.Duration) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(cert *x509.Certificate) error {
		now := time.Now()

		if cert.NotBefore.After(now) {
			return fmt.Errorf("incorrect certificate validity period; begins in the future: %s", cert.NotBefore)
		}

		// NOTE: 2 minutes should be plenty to cover for slow hardware that takes long to start
		// the test and then get to this check.
		if now.Sub(cert.NotBefore) > (2 * time.Minute) {
			return fmt.Errorf("incorrect certificate validity period; begins more than 2 minutes in the past: %s", cert.NotBefore)
		}

		if actual := cert.NotAfter.Sub(cert.NotBefore); actual != expected {
			return fmt.Errorf("incorrect certificate validity duration: expected %s, got %s", expected, actual)
		}

		return nil
	})
}

func testCheckPEMCertificateAgainstPEMRootCA(name, key string, rootCA []byte) r.TestCheckFunc {
	return testCheckPEMCertificateWith(name, key, func(crt *x509.Certificate) error {
		// Certificate verification must fail if no CA Cert Pool is provided
		_, err := crt.Verify(x509.VerifyOptions{})
		if err == nil {
			return fmt.Errorf("incorrectly verified certificate")
		} else if !errors.Is(err, x509.UnknownAuthorityError{Cert: crt}) {
			return fmt.Errorf("incorrect verify error: expected UnknownAuthorityError, got %v", err)
		}

		// Certificate verification must fail if an empty CA Cert Pool is provided
		_, err = crt.Verify(x509.VerifyOptions{Roots: x509.NewCertPool()})
		if err == nil {
			return fmt.Errorf("incorrectly verified certificate")
		} else if !errors.Is(err, x509.UnknownAuthorityError{Cert: crt}) {
			return fmt.Errorf("incorrect verify error: expected UnknownAuthorityError, got %v", err)
		}

		// Certification verification must succeed now that we are providing the correct CA Cert Pool
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(rootCA)
		if _, err = crt.Verify(x509.VerifyOptions{Roots: certPool}); err != nil {
			return fmt.Errorf("verify failed: %s", err)
		}

		return nil
	})
}

func compareCertSubjects(expected, actualSubject *pkix.Name) error {
	if expected.SerialNumber != "" && expected.SerialNumber != actualSubject.SerialNumber {
		return fmt.Errorf("incorrect subject serial number: expected %v, got %v", expected.SerialNumber, actualSubject.SerialNumber)
	}
	if expected.CommonName != "" && expected.CommonName != actualSubject.CommonName {
		return fmt.Errorf("incorrect subject common name: expected %v, got %v", expected.CommonName, actualSubject.CommonName)
	}
	if len(expected.Organization) > 0 && !reflect.DeepEqual(expected.Organization, actualSubject.Organization) {
		return fmt.Errorf("incorrect subject organization: expected %v, got %v", expected.Organization, actualSubject.Organization)
	}
	if len(expected.OrganizationalUnit) > 0 && !reflect.DeepEqual(expected.OrganizationalUnit, actualSubject.OrganizationalUnit) {
		return fmt.Errorf("incorrect subject organizational unit: expected %v, got %v", expected.OrganizationalUnit, actualSubject.OrganizationalUnit)
	}
	if len(expected.StreetAddress) > 0 && !reflect.DeepEqual(expected.StreetAddress, actualSubject.StreetAddress) {
		return fmt.Errorf("incorrect subject street address: expected %v, got %v", expected.StreetAddress, actualSubject.StreetAddress)
	}
	if len(expected.Locality) > 0 && !reflect.DeepEqual(expected.Locality, actualSubject.Locality) {
		return fmt.Errorf("incorrect subject locality: expected %v, got %v", expected.Locality, actualSubject.Locality)
	}
	if len(expected.Province) > 0 && !reflect.DeepEqual(expected.Province, actualSubject.Province) {
		return fmt.Errorf("incorrect subject province: expected %v, got %v", expected.Province, actualSubject.Province)
	}
	if len(expected.Country) > 0 && !reflect.DeepEqual(expected.Country, actualSubject.Country) {
		return fmt.Errorf("incorrect subject country: expected %v, got %v", expected.Country, actualSubject.Country)
	}
	if len(expected.PostalCode) > 0 && !reflect.DeepEqual(expected.PostalCode, actualSubject.PostalCode) {
		return fmt.Errorf("incorrect subject postal code: expected %v, got %v", expected.PostalCode, actualSubject.PostalCode)
	}

	return nil
}

func compareCertDNSNames(expected, actual []string) error {
	if len(expected) != len(actual) {
		return fmt.Errorf("incorrect DNS names: expected %v, got %v", expected, actual)
	}

	for i := range expected {
		if !strings.EqualFold(expected[i], actual[i]) {
			return fmt.Errorf("incorrect DNS names: expected %v, got %v", expected, actual)
		}
	}

	return nil
}

func compareCertIPAddresses(expected, actual []net.IP) error {
	if len(expected) != len(actual) {
		return fmt.Errorf("incorrect IP addresses: expected %v, got %v", expected, actual)
	}

	for i := range expected {
		if !expected[i].Equal(actual[i]) {
			return fmt.Errorf("incorrect IP addresses: expected %v, got %v", expected, actual)
		}
	}

	return nil
}

func compareCertURIs(expected, actual []*url.URL) error {
	if len(expected) != len(actual) {
		return fmt.Errorf("incorrect URIs: expected %v, got %v", expected, actual)
	}

	for i := range expected {
		if !strings.EqualFold(expected[i].String(), actual[i].String()) {
			return fmt.Errorf("incorrect URIs: expected %v, got %v", expected, actual)
		}
	}

	return nil
}

func compareExtKeyUsages(expected, actual []x509.ExtKeyUsage) error {
	if len(expected) != len(actual) {
		return fmt.Errorf("incorrect Extended Key Usages: expected %v, got %v", expected, actual)
	}

	for i := range expected {
		if expected[i] != actual[i] {
			return fmt.Errorf("incorrect Extended Key Usages: expected %v, got %v", expected, actual)
		}
	}

	return nil
}
