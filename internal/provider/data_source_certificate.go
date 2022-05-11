package provider

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func dataSourceCertificate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceCertificateRead,

		Description: "Get information about the TLS certificates securing a host.\n\n" +
			"Use this data source to get information, such as SHA1 fingerprint or serial number, " +
			"about the TLS certificates that protects a URL.",

		Schema: map[string]*schema.Schema{
			"url": {
				Type:     schema.TypeString,
				Optional: true,
				Description: "URL of the endpoint to get the certificates from. " +
					fmt.Sprintf("Accepted schemes are: `%s`. ", strings.Join(SupportedURLSchemesStr(), "`, `")) +
					"For scheme `https://` it will use the HTTP protocol and apply the `proxy` configuration " +
					"of the provider, if set. For scheme `tls://` it will instead use a secure TCP socket.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.IsURLWithScheme(SupportedURLSchemesStr())),
				ExactlyOneOf:     []string{"content", "url"},
			},
			"content": {
				Type:         schema.TypeString,
				Optional:     true,
				Description:  "The content of the certificate in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
				ExactlyOneOf: []string{"content", "url"},
			},
			"verify_chain": {
				Type:          schema.TypeBool,
				Optional:      true,
				Default:       true,
				Description:   "Whether to verify the certificate chain while parsing it or not (default: `true`).",
				ConflictsWith: []string{"content"},
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
						"cert_pem": {
							Type:     schema.TypeString,
							Computed: true,
							Description: "Certificate data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
								"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
								"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
								"value append a `\\n` at the end of the PEM. " +
								"In case this disrupts your use case, we recommend using " +
								"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
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

func dataSourceCertificateRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	config := m.(*providerConfig)

	var certs []interface{}

	if v, ok := d.GetOk("content"); ok {
		block, _ := pem.Decode([]byte(v.(string)))
		if block == nil {
			return diag.Errorf("failed to decode pem content")
		}

		preamble, err := PEMBlockToPEMPreamble(block)
		if err != nil {
			return diag.FromErr(err)
		}

		if preamble != PreambleCertificate {
			return diag.Errorf("PEM must be of type 'CERTIFICATE'")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return diag.Errorf("unable to parse the certificate %v", err)
		}

		certs = []interface{}{certificateToMap(cert)}
	} else {
		targetURL, err := url.Parse(d.Get("url").(string))
		if err != nil {
			return diag.FromErr(err)
		}

		// Determine if we should verify the chain of certificates, or skip said verification
		shouldVerifyChain := d.Get("verify_chain").(bool)

		// Ensure a port is set on the URL, or return an error
		var peerCerts []*x509.Certificate
		switch targetURL.Scheme {
		case HTTPSScheme.String():
			if targetURL.Port() == "" {
				targetURL.Host += ":443"
			}

			// TODO remove this branch and default to use `fetchPeerCertificatesViaHTTPS`
			//   as part of https://github.com/hashicorp/terraform-provider-tls/issues/183
			if config.isProxyConfigured() {
				peerCerts, err = fetchPeerCertificatesViaHTTPS(targetURL, shouldVerifyChain, config)
			} else {
				peerCerts, err = fetchPeerCertificatesViaTLS(targetURL, shouldVerifyChain)
			}
		case TLSScheme.String():
			if targetURL.Port() == "" {
				return diag.Errorf("port missing from URL: %s", targetURL.String())
			}

			peerCerts, err = fetchPeerCertificatesViaTLS(targetURL, shouldVerifyChain)
		default:
			// NOTE: This should never happen, given we validate this at the schema level
			return diag.Errorf("unsupported scheme: %s", targetURL.Scheme)
		}
		if err != nil {
			return diag.FromErr(err)
		}

		// Convert peer certificates to a simple map
		certs = make([]interface{}, len(peerCerts))
		for i, peerCert := range peerCerts {
			certs[len(peerCerts)-i-1] = certificateToMap(peerCert)
		}
	}

	err := d.Set("certificates", certs)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(hashForState(fmt.Sprintf("%v", certs)))

	return nil
}

func fetchPeerCertificatesViaTLS(targetURL *url.URL, shouldVerifyChain bool) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", targetURL.Host, &tls.Config{
		InsecureSkipVerify: !shouldVerifyChain,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to execute TLS connection towards %s: %w", targetURL.Host, err)
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}

func fetchPeerCertificatesViaHTTPS(targetURL *url.URL, shouldVerifyChain bool, config *providerConfig) ([]*x509.Certificate, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !shouldVerifyChain,
			},
			Proxy: config.proxyForRequestFunc(),
		},
	}

	// First attempting an HTTP HEAD: if it fails, ignore errors and move on
	resp, err := client.Head(targetURL.String())
	if err == nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		defer resp.Body.Close()
		return resp.TLS.PeerCertificates, nil
	}

	// Then attempting HTTP GET: if this fails we will than report the error
	resp, err = client.Get(targetURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates from URL '%s': %w", targetURL.Scheme, err)
	}
	defer resp.Body.Close()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		return resp.TLS.PeerCertificates, nil
	}

	return nil, fmt.Errorf("got back response (status: %s) with no certificates from URL '%s': %w", resp.Status, targetURL.Scheme, err)
}
