package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCertRequest() *schema.Resource {
	s := map[string]*schema.Schema{
		"cert_request_pem": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "The certificate request data in " +
				"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
				"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
				"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
				"value append a `\\n` at the end of the PEM. " +
				"In case this disrupts your use case, we recommend using " +
				"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
		},

		"id": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "Unique identifier for this resource: " +
				"hexadecimal representation of the SHA1 checksum of the resource.",
		},
	}
	setCertificateSubjectSchema(s)

	return &schema.Resource{
		CreateContext: createCertRequest,
		DeleteContext: deleteCertRequest,
		ReadContext:   readCertRequest,

		Description: "Creates a Certificate Signing Request (CSR) in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.\n\n" +
			"PEM is the typical format used to request a certificate from a Certificate Authority (CA).\n\n" +
			"This resource is intended to be used in conjunction with a Terraform provider " +
			"for a particular certificate authority in order to provision a new certificate.",

		Schema: s,
	}
}

func createCertRequest(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	key, algorithm, err := parsePrivateKeyPEM([]byte(d.Get("private_key_pem").(string)))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("key_algorithm", algorithm); err != nil {
		return diag.Errorf("error setting value on key 'key_algorithm': %s", err)
	}

	// Look for a 'subject' block
	subject, err := getSubjectDistinguishedNames(d)
	if err != nil {
		return diag.FromErr(err)
	}

	// Add a `Subject` to the `Certificate` only if it was provided
	certReq := x509.CertificateRequest{}
	if subject != nil {
		certReq.Subject = *subject
	}

	dnsNamesI := d.Get("dns_names").([]interface{})
	for _, nameI := range dnsNamesI {
		certReq.DNSNames = append(certReq.DNSNames, nameI.(string))
	}
	ipAddressesI := d.Get("ip_addresses").([]interface{})
	for _, ipStrI := range ipAddressesI {
		ip := net.ParseIP(ipStrI.(string))
		if ip == nil {
			return diag.Errorf("invalid IP address %#v", ipStrI.(string))
		}
		certReq.IPAddresses = append(certReq.IPAddresses, ip)
	}
	urisI := d.Get("uris").([]interface{})
	for _, uriI := range urisI {
		uri, err := url.Parse(uriI.(string))
		if err != nil {
			return diag.Errorf("invalid URI %#v", uriI.(string))
		}
		certReq.URIs = append(certReq.URIs, uri)
	}

	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &certReq, key)
	if err != nil {
		return diag.Errorf("error creating certificate request: %s", err)
	}
	certReqPem := string(pem.EncodeToMemory(&pem.Block{Type: PreambleCertificateRequest.String(), Bytes: certReqBytes}))

	d.SetId(hashForState(string(certReqBytes)))

	if err := d.Set("cert_request_pem", certReqPem); err != nil {
		return diag.Errorf("error setting value on key 'cert_request_pem': %s", err)
	}

	return nil
}

func deleteCertRequest(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

func readCertRequest(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	return nil
}
