package provider

import (
	"crypto/tls"
	"net/url"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func dataSourceCertificate() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCertificateRead,

		Description: "Get information about the TLS certificates securing a host.\n\n" +
			"Use this data source to get information, such as SHA1 fingerprint or serial number, " +
			"about the TLS certificates that protects an HTTPS website.",

		Schema: map[string]*schema.Schema{
			"url": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "The URL of the website to get the certificates from.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.IsURLWithHTTPS),
			},
			"verify_chain": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     true,
				Description: "Whether to verify the certificate chain while parsing it or not (default: `true`).",
			},
			"certificates": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"signature_algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The algorithm used to sign the certificate.",
						},
						"public_key_algorithm": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The key algorithm used to create the certificate.",
						},
						"serial_number": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "Number that uniquely identifies the certificate with the CA's system. " +
								"The `format` function can be used to convert this _base 10_ number " +
								"into other bases, such as hex.",
						},
						"is_ca": {
							Type:        schema.TypeBool,
							Computed:    true,
							Description: "`true` if the certificate is of a CA (Certificate Authority).",
						},
						"version": {
							Type:        schema.TypeInt,
							Computed:    true,
							Description: "The version the certificate is in.",
						},
						"issuer": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "Who verified and signed the certificate, roughly following " +
								"[RFC2253](https://tools.ietf.org/html/rfc2253).",
						},
						"subject": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "The entity the certificate belongs to, roughly following " +
								"[RFC2253](https://tools.ietf.org/html/rfc2253).",
						},
						"not_before": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "The time after which the certificate is valid, as an " +
								"[RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
						},
						"not_after": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "The time until which the certificate is invalid, as an " +
								"[RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
						},
						"sha1_fingerprint": {
							Type:        schema.TypeString,
							Computed:    true,
							Description: "The SHA1 fingerprint of the public key of the certificate.",
						},
					},
				},
				Description: "The certificates protecting the site, with the root of the chain first.",
			},
			"id": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Unique identifier of this data source: " +
					"randomly generated string (UTC time when data source was read).",
			},
		},
	}
}

func dataSourceCertificateRead(d *schema.ResourceData, _ interface{}) error {
	u, err := url.Parse(d.Get("url").(string))
	if err != nil {
		return err
	}
	if u.Port() == "" {
		u.Host += ":443"
	}

	verifyChain := d.Get("verify_chain").(bool)

	conn, err := tls.Dial("tcp", u.Host, &tls.Config{InsecureSkipVerify: !verifyChain})
	if err != nil {
		return err
	}
	defer conn.Close()
	state := conn.ConnectionState()

	var certs []interface{}
	for i := len(state.PeerCertificates) - 1; i >= 0; i-- {
		certs = append(certs, certificateToMap(state.PeerCertificates[i]))
	}

	err = d.Set("certificates", certs)
	if err != nil {
		return err
	}

	d.SetId(time.Now().UTC().String())

	return nil
}
