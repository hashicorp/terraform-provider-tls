package provider

import (
	"crypto/x509"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceLocallySignedCert() *schema.Resource {
	s := map[string]*schema.Schema{}

	setCertificateCommonSchema(s)

	s["cert_request_pem"] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
		StateFunc: func(v interface{}) string {
			return hashForState(v.(string))
		},
		Description: "Certificate request data in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
	}

	s["ca_key_algorithm"] = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    true,
		Description: "Name of the algorithm used when generating the private key provided in `ca_private_key_pem`.",
	}

	s["ca_private_key_pem"] = &schema.Schema{
		Type:      schema.TypeString,
		Required:  true,
		ForceNew:  true,
		Sensitive: true,
		StateFunc: func(v interface{}) string {
			return hashForState(v.(string))
		},
		Description: "Private key of the Certificate Authority (CA) used to sign the certificate, " +
			"in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
	}

	s["ca_cert_pem"] = &schema.Schema{
		Type:     schema.TypeString,
		Required: true,
		ForceNew: true,
		StateFunc: func(v interface{}) string {
			return hashForState(v.(string))
		},
		Description: "Certificate data of the Certificate Authority (CA) " +
			"in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
	}

	return &schema.Resource{
		Create:        createLocallySignedCert,
		Delete:        deleteCertificate,
		Read:          readCertificate,
		Update:        updateCertificate,
		CustomizeDiff: customizeCertificateDiff,
		Schema:        s,
		Description: "Creates a TLS certificate in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) " +
			"format using a Certificate Signing Request (CSR) and signs it with a provided " +
			"(local) Certificate Authority (CA).",
	}
}

func createLocallySignedCert(d *schema.ResourceData, meta interface{}) error {
	certReq, err := parseCertificateRequest(d, "cert_request_pem")
	if err != nil {
		return err
	}
	caKey, _, err := parsePrivateKeyPEM([]byte(d.Get("ca_private_key_pem").(string)))
	if err != nil {
		return err
	}
	caCert, err := parseCertificate(d, "ca_cert_pem")
	if err != nil {
		return err
	}

	cert := x509.Certificate{
		Subject:               certReq.Subject,
		DNSNames:              certReq.DNSNames,
		IPAddresses:           certReq.IPAddresses,
		URIs:                  certReq.URIs,
		BasicConstraintsValid: true,
	}

	return createCertificate(d, &cert, caCert, certReq.PublicKey, caKey)
}
