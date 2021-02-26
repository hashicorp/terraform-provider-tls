package provider

import (
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"net/url"
	"time"
)

func dataSourceTlsCertificate() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceTlsCertificateRead,
		Schema: map[string]*schema.Schema{
			"url": {
				Type:     schema.TypeString,
				Required: true,
			},
			"verify_chain": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
			"certificates": {
				Type:     schema.TypeList,
				Computed: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"signature_algorithm": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"public_key_algorithm": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"serial_number": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"is_ca": {
							Type:     schema.TypeBool,
							Computed: true,
						},
						"version": {
							Type:     schema.TypeInt,
							Computed: true,
						},
						"issuer": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"subject": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"not_before": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"not_after": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"sha1_fingerprint": {
							Type:     schema.TypeString,
							Computed: true,
						},
						"pem": {
							Type:     schema.TypeString,
							Computed: true,
						},
					},
				},
			},
		},
	}
}

func dataSourceTlsCertificateRead(d *schema.ResourceData, _ interface{}) error {
	u, err := url.Parse(d.Get("url").(string))
	if err != nil {
		return err
	}
	if u.Scheme != "https" {
		return fmt.Errorf("invalid scheme")
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
		certs = append(certs, parsePeerCertificate(state.PeerCertificates[i]))
	}

	err = d.Set("certificates", certs)
	if err != nil {
		return err
	}

	d.SetId(time.Now().UTC().String())

	return nil
}

func parsePeerCertificate(cert *x509.Certificate) map[string]interface{} {
	ret := map[string]interface{}{
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"serial_number":        cert.SerialNumber.String(),
		"is_ca":                cert.IsCA,
		"version":              cert.Version,
		"issuer":               cert.Issuer.String(),
		"subject":              cert.Subject.String(),
		"not_before":           cert.NotBefore.Format(time.RFC3339),
		"not_after":            cert.NotAfter.Format(time.RFC3339),
		"sha1_fingerprint":     fmt.Sprintf("%x", sha1.Sum(cert.Raw)),
		"pem":                  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
	}

	return ret
}
