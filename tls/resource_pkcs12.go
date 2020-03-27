package tls

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourcePkcs12() *schema.Resource {
	return &schema.Resource{
		Create: resourcePkcs12Create,
		Read:   resourcePkcs12Read,
		Update: resourcePkcs12Update,
		Delete: resourcePkcs12Delete,

		Schema: map[string]*schema.Schema{
			"private_key_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "PEM-encoded private key",
				Sensitive:   true,
			},
			"certificate_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "PEM-encoded certificate",
			},
			"ca_certificate_pem": {
				Type:        schema.TypeList,
				Required:    true,
				Description: "PEM-encoded CA certificate",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},

			"certificate_p12": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},

			"certificate_p12_password": {
				Type:      schema.TypeString,
				Optional:  true,
				Default:   "",
				Sensitive: true,
			},
		},
	}
}

func resourcePkcs12Create(d *schema.ResourceData, meta interface{}) error {

	private_key, err := privateKeyFromPEM([]byte(d.Get("private_key_pem").(string)))
	if err != nil {
		return err
	}

	block, rest := pem.Decode([]byte(d.Get("certificate_pem").(string)))

	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	pemBundle = []byte(d.Get("ca_certificate_pem").(string))
	caCerts, err = certificatesFromPEM(pemBundle)
	if err != nil {
		return err
	}
	password := d.Get("certificate_p12_password").(string)

	pfxB64, err := toPfx(private_key, cert, caCerts, password)
	if err != nil {
		return err
	}

	d.Set("certificate_p12", string(pfxB64))
	return nil
}

func resourcePkcs12Read(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourcePkcs12Update(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func resourcePkcs12Delete(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

// privateKeyFromPEM converts a PEM block into a crypto.PrivateKey.
func privateKeyFromPEM(pemData []byte) (crypto.PrivateKey, error) {
	var result *pem.Block
	rest := pemData
	for {
		result, rest = pem.Decode(rest)
		if result == nil {
			return nil, fmt.Errorf("Cannot decode supplied PEM data")
		}
		switch result.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(result.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(result.Bytes)
		}
	}
}

func certificatesFromPEM(pemData []byte) ([]*Certificate, error) {
	var certificates []*x509.Certificate
	var certDERBlock *pem.Block

	for {
		certDERBlock, bundle = pem.Decode(bundle)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(certDERBlock.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	if len(certificates) == 0 {
		return nil, errors.New("no certificates were found while parsing the bundle")
	}

	return certificates, nil
}
