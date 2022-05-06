package provider

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"regexp"
	"strings"

	r "github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func testCheckPEMCertificateFormat(name, key string, expected PEMPreamble) r.TestCheckFunc {
	return r.TestMatchResourceAttr(name, key, regexp.MustCompile(fmt.Sprintf(`^-----BEGIN %[1]s----(.|\s)+-----END %[1]s-----\n$`, expected)))
}

func testCheckPEMCertificateRequestSubject(name, key string, expected *pkix.Name) r.TestCheckFunc {
	return r.TestCheckResourceAttrWith(name, key, func(value string) error {
		block, _ := pem.Decode([]byte(value))
		actual, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing CSR: %s", err)
		}
		return compareCertSubjects(expected, &actual.Subject)
	})
}

func testCheckPEMCertificateRequestDNSNames(name, key string, expected []string) r.TestCheckFunc {
	return r.TestCheckResourceAttrWith(name, key, func(value string) error {
		block, _ := pem.Decode([]byte(value))
		actual, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing CSR: %s", err)
		}
		return compareCertDNSNames(expected, actual.DNSNames)
	})
}

func testCheckPEMCertificateRequestIPAddresses(name, key string, expected []net.IP) r.TestCheckFunc {
	return r.TestCheckResourceAttrWith(name, key, func(value string) error {
		block, _ := pem.Decode([]byte(value))
		actual, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing CSR: %s", err)
		}
		return compareCertIPAddresses(expected, actual.IPAddresses)
	})
}

func testCheckPEMCertificateRequestURIs(name, key string, expected []*url.URL) r.TestCheckFunc {
	return r.TestCheckResourceAttrWith(name, key, func(value string) error {
		block, _ := pem.Decode([]byte(value))
		actual, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return fmt.Errorf("error parsing CSR: %s", err)
		}
		return compareCertURIs(expected, actual.URIs)
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
		return fmt.Errorf("incorrect IP addresses: expected %v, got %v", expected, actual)
	}

	for i := range expected {
		if !strings.EqualFold(expected[i], actual[i]) {
			return fmt.Errorf("incorrect IP addresses: expected %v, got %v", expected, actual)
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
			return fmt.Errorf("incorrect IP addresses: expected %v, got %v", expected, actual)
		}
	}

	return nil
}
