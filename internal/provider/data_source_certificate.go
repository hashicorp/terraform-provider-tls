package provider

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func dataSourceCertificate() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceCertificateRead,

		Description: "Get information about the TLS certificates securing a host.\n\n" +
			"Use this data source to get information, such as SHA1 fingerprint or serial number, " +
			"about the TLS certificates that protects a URL.",

		Schema: map[string]*schema.Schema{
			"url": {
				Type:     schema.TypeString,
				Required: true,
				Description: "URL of the endpoint to get the certificates from. " +
					fmt.Sprintf("Accepted schemes are: `%s`. ", strings.Join(SupportedURLSchemesStr(), "`, `")) +
					"For scheme `https://` it will use the HTTP protocol and apply the `proxy` configuration " +
					"of the provider, if set. For scheme `tls://` it will instead use a secure TCP socket.",
				ValidateDiagFunc: validation.ToDiagFunc(validation.IsURLWithScheme(SupportedURLSchemesStr())),
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

func dataSourceCertificateRead(d *schema.ResourceData, m interface{}) error {
	config := m.(*providerConfig)

	targetURL, err := url.Parse(d.Get("url").(string))
	if err != nil {
		return err
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
			return fmt.Errorf("port missing from URL: %s", targetURL.String())
		}

		peerCerts, err = fetchPeerCertificatesViaTLS(targetURL, shouldVerifyChain)
	default:
		// NOTE: This should never happen, given we validate this at the schema level
		return fmt.Errorf("unsupported scheme: %s", targetURL.Scheme)
	}
	if err != nil {
		return err
	}

	// Convert peer certificates to a simple map
	certs := make([]interface{}, len(peerCerts))
	for i, peerCert := range peerCerts {
		certs[len(peerCerts)-i-1] = certificateToMap(peerCert)
	}
	err = d.Set("certificates", certs)
	if err != nil {
		return err
	}

	d.SetId(time.Now().UTC().String())

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

	// Fist attempting an HTTP HEAD: if it fails, ignore errors and move on
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
