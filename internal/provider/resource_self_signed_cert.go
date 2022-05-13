package provider

import (
	"context"
	"crypto/x509"
	"net"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceSelfSignedCert() *schema.Resource {
	s := map[string]*schema.Schema{}

	setCertificateCommonSchema(s)
	setCertificateSubjectSchema(s)

	return &schema.Resource{
		CreateContext: createSelfSignedCert,
		DeleteContext: deleteCertificate,
		ReadContext:   readCertificate,
		UpdateContext: updateCertificate,
		CustomizeDiff: customizeCertificateDiff,
		Schema:        s,
		Description: "Creates a **self-signed** TLS certificate in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
	}
}

func createSelfSignedCert(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	key, algorithm, err := parsePrivateKeyPEM([]byte(d.Get("private_key_pem").(string)))
	if err != nil {
		return diag.FromErr(err)
	}

	if err := d.Set("key_algorithm", algorithm); err != nil {
		return diag.Errorf("error setting value on key 'key_algorithm': %s", err)
	}

	// Look for a 'subject' block
	subject := createSubjectDistinguishedNames(d.Get("subject").([]interface{}))

	// Add a `Subject` to the `Certificate` only if it was provided
	cert := x509.Certificate{BasicConstraintsValid: true}
	if subject != nil {
		cert.Subject = *subject
	}

	dnsNamesI := d.Get("dns_names").([]interface{})
	for _, nameI := range dnsNamesI {
		cert.DNSNames = append(cert.DNSNames, nameI.(string))
	}
	ipAddressesI := d.Get("ip_addresses").([]interface{})
	for _, ipStrI := range ipAddressesI {
		ip := net.ParseIP(ipStrI.(string))
		if ip == nil {
			return diag.Errorf("invalid IP address %#v", ipStrI.(string))
		}
		cert.IPAddresses = append(cert.IPAddresses, ip)
	}
	urisI := d.Get("uris").([]interface{})
	for _, uriStrI := range urisI {
		uri, err := url.Parse(uriStrI.(string))
		if err != nil {
			return diag.Errorf("invalid URI %#v", uriStrI.(string))
		}
		cert.URIs = append(cert.URIs, uri)
	}

	publicKey, err := privateKeyToPublicKey(key)
	if err != nil {
		return diag.Errorf("failed to get public key from private key: %v", err)
	}
	return createCertificate(d, &cert, &cert, publicKey, key)
}
