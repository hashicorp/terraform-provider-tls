package provider

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net"
	"net/url"
)

func resourceCertRequest() *schema.Resource {
	return &schema.Resource{
		Create: CreateCertRequest,
		Delete: DeleteCertRequest,
		Read:   ReadCertRequest,

		Description: "Creates a Certificate Signing Request (CSR) in PEM format.\n\n" +
			"PEM is the typical format used to request a certificate from a Certificate Authority (CA).\n\n" +
			"This resource is intended to be used in conjunction with a Terraform provider " +
			"for a particular certificate authority in order to provision a new certificate.",

		Schema: map[string]*schema.Schema{

			"dns_names": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of DNS names for which a certificate is being requested (i.e. certificate subjects).",
			},

			"ip_addresses": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of IP addresses for which a certificate is being requested (i.e. certificate subjects).",
			},

			"uris": {
				Type:     schema.TypeList,
				Optional: true,
				ForceNew: true,
				Elem: &schema.Schema{
					Type: schema.TypeString,
				},
				Description: "List of URIs for which a certificate is being requested (i.e. certificate subjects).",
			},

			"key_algorithm": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Name of the algorithm used when generating the private key provided in `private_key_pem`.",
			},

			"private_key_pem": {
				Type:      schema.TypeString,
				Required:  true,
				ForceNew:  true,
				Sensitive: true,
				StateFunc: func(v interface{}) string {
					return hashForState(v.(string))
				},
				Description: "PEM-encoded private key that the certificate will belong to. " +
					"This can be read from a separate file using the `file` interpolation function. " +
					"Only an irreversible secure hash of the private key will be stored in the Terraform state.",
			},

			"subject": {
				Type:     schema.TypeList,
				Required: true,
				ForceNew: true,
				Elem:     subjectAttributesResource,
				Description: "The subject for which a certificate is being requested. " +
					"The acceptable arguments are all optional and their naming is based upon " +
					"[Issuer Distinguished Names (RFC5280)](https://tools.ietf.org/html/rfc5280#section-4.1.2.4) section.",
			},

			"cert_request_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The certificate request data in PEM format.",
			},

			"id": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Unique identifier for this resource: " +
					"hexadecimal representation of the SHA1 checksum of the resource.",
			},
		},
	}
}

func CreateCertRequest(d *schema.ResourceData, meta interface{}) error {
	key, err := parsePrivateKey(d, "private_key_pem", "key_algorithm")
	if err != nil {
		return err
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
	certReqPem := string(pem.EncodeToMemory(&pem.Block{Type: CertificateRequest.String(), Bytes: certReqBytes}))

	d.SetId(hashForState(string(certReqBytes)))

	if err := d.Set("cert_request_pem", certReqPem); err != nil {
		return fmt.Errorf("error setting value on key 'cert_request_pem': %s", err)
	}

	return nil
}

func DeleteCertRequest(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func ReadCertRequest(d *schema.ResourceData, meta interface{}) error {
	return nil
}
