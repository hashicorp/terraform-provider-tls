package tls

import (
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceCertRevocationList() *schema.Resource {
	s := map[string]*schema.Schema{
		"certs_to_revoke": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Required:    true,
			Description: "PEM-encoded certificates to be revoked",
			ForceNew:    true,
			StateFunc: func(v interface{}) string {
				return hashForState(strings.Join(v.([]string), ","))
			},
		},
		"early_renewal_hours": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "Number of hours before the CRL expiry when a new CRL will be generated",
		},
		"validity_period_hours": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "Number of hours that the CRL will remain valid for",
			ForceNew:    true,
		},
		"validity_start_time": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"validity_end_time": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"ready_for_renewal": {
			Type:     schema.TypeBool,
			Computed: true,
		},
		"crl_pem": {
			Type:     schema.TypeString,
			Computed: true,
		},
		"ca_cert_pem": &schema.Schema{
			Type:        schema.TypeString,
			Required:    true,
			Description: "PEM-encoded CA certificate",
			ForceNew:    true,
			StateFunc: func(v interface{}) string {
				return hashForState(v.(string))
			},
		},
		"ca_private_key_pem": &schema.Schema{
			Type:        schema.TypeString,
			Required:    true,
			Description: "PEM-encoded CA private key used to sign the CRL",
			ForceNew:    true,
			Sensitive:   true,
			StateFunc: func(v interface{}) string {
				return hashForState(v.(string))
			},
		},
		"ca_key_algorithm": &schema.Schema{
			Type:        schema.TypeString,
			Required:    true,
			Description: "Name of the algorithm used by the CA private key",
			ForceNew:    true,
		},
	}

	return &schema.Resource{
		Create:        CreateCRL,
		Delete:        DeleteCRL,
		Read:          ReadCRL,
		Update:        UpdateCRL,
		CustomizeDiff: CustomizeCertificateDiff,
		Schema:        s,
	}
}

func CreateCRL(d *schema.ResourceData, meta interface{}) error {
	notBefore := now()

	certsToRevoke := make([]pkix.RevokedCertificate, 0)
	for _, vi := range d.Get("certs_to_revoke").([]interface{}) {
		certificate, err := decodeCertificateFromBytes([]byte(vi.(string)))
		if err != nil {
			return fmt.Errorf("failed to parse %q field: %w", "certs_to_revoke", err)
		}
		certsToRevoke = append(certsToRevoke, pkix.RevokedCertificate{
			SerialNumber:   certificate.SerialNumber,
			RevocationTime: notBefore,
		})
	}
	caKey, err := parsePrivateKey(d, "ca_private_key_pem", "ca_key_algorithm")
	if err != nil {
		return fmt.Errorf("failed to parse %q field: %w", "ca_private_key_pem", err)
	}
	caCert, err := parseCertificate(d, "ca_cert_pem")
	if err != nil {
		return fmt.Errorf("failed to parse %q field: %w", "ca_cert_pem", err)
	}

	notAfter := notBefore.Add(time.Duration(d.Get("validity_period_hours").(int)) * time.Hour)
	validFromBytes, err := notBefore.MarshalText()
	if err != nil {
		return err
	}
	validToBytes, err := notAfter.MarshalText()
	if err != nil {
		return err
	}

	crlBytes, err := caCert.CreateCRL(rand.Reader, caKey, certsToRevoke, notBefore, notAfter)
	if err != nil {
		return fmt.Errorf("failed to create crl: %w", err)
	}

	crlPem := string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes}))

	d.SetId(hashForState(string(crlBytes)))
	d.Set("crl_pem", crlPem)
	d.Set("ready_for_renewal", false)
	d.Set("validity_start_time", string(validFromBytes))
	d.Set("validity_end_time", string(validToBytes))
	return nil
}

func DeleteCRL(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func ReadCRL(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func UpdateCRL(d *schema.ResourceData, meta interface{}) error {
	return nil
}
