package provider

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCertRequest() *schema.Resource {
	s := map[string]*schema.Schema{
		"cert_request_pem": {
			Type:     schema.TypeString,
			Computed: true,
			Description: "The certificate request data in " +
				"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
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
		Create: createCertRequest,
		Delete: deleteCertRequest,
		Read:   readCertRequest,

		Description: "Creates a Certificate Signing Request (CSR) in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.\n\n" +
			"PEM is the typical format used to request a certificate from a Certificate Authority (CA).\n\n" +
			"This resource is intended to be used in conjunction with a Terraform provider " +
			"for a particular certificate authority in order to provision a new certificate.",

		Schema: s,
	}
}

func createCertRequest(d *schema.ResourceData, meta interface{}) error {
	key, algorithm, err := parsePrivateKeyPEM([]byte(d.Get("private_key_pem").(string)))
	if err != nil {
		return err
	}

	if err := d.Set("key_algorithm", algorithm); err != nil {
		return fmt.Errorf("error setting value on key 'key_algorithm': %s", err)
	}

	subjectConfs := d.Get("subject").([]interface{})
	if len(subjectConfs) != 1 {
		return fmt.Errorf("must have exactly one 'subject' block")
	}
	subjectConf, ok := subjectConfs[0].(map[string]interface{})
	if !ok {
		return fmt.Errorf("subject block cannot be empty")
	}
	subject := distinguishedNamesFromSubjectAttributes(subjectConf)

	certReq := x509.CertificateRequest{
		Subject: *subject,
	}

	dnsNamesI := d.Get("dns_names").([]interface{})
	for _, nameI := range dnsNamesI {
		certReq.DNSNames = append(certReq.DNSNames, nameI.(string))
	}
	ipAddressesI := d.Get("ip_addresses").([]interface{})
	for _, ipStrI := range ipAddressesI {
		ip := net.ParseIP(ipStrI.(string))
		if ip == nil {
			return fmt.Errorf("invalid IP address %#v", ipStrI.(string))
		}
		certReq.IPAddresses = append(certReq.IPAddresses, ip)
	}
	urisI := d.Get("uris").([]interface{})
	for _, uriI := range urisI {
		uri, err := url.Parse(uriI.(string))
		if err != nil {
			return fmt.Errorf("invalid URI %#v", uriI.(string))
		}
		certReq.URIs = append(certReq.URIs, uri)
	}

	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &certReq, key)
	if err != nil {
		return fmt.Errorf("error creating certificate request: %s", err)
	}
	certReqPem := string(pem.EncodeToMemory(&pem.Block{Type: PreambleCertificateRequest.String(), Bytes: certReqBytes}))

	d.SetId(hashForState(string(certReqBytes)))

	if err := d.Set("cert_request_pem", certReqPem); err != nil {
		return fmt.Errorf("error setting value on key 'cert_request_pem': %s", err)
	}

	return nil
}

func deleteCertRequest(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func readCertRequest(d *schema.ResourceData, meta interface{}) error {
	return nil
}
