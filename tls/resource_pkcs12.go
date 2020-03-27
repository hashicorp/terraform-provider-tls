package tls

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"software.sslmate.com/src/go-pkcs12"
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
	var cert *x509.Certificate

	private_key, err := privateKeyFromPEM([]byte(d.Get("private_key_pem").(string)))
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(d.Get("certificate_pem").(string)))

	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}

	pemData := []byte(d.Get("ca_certificate_pem").(string))
	caCerts, err := certificatesFromPEM(pemData)
	if err != nil {
		return err
	}
	password := d.Get("certificate_p12_password").(string)

	pkcs12B64, err := toPkcs12(private_key, cert, caCerts, password)
	if err != nil {
		return err
	}

	d.Set("certificate_p12", string(pkcs12B64))
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
	var block *pem.Block
	rest := pemData

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, fmt.Errorf("Cannot decode supplied PEM data")
		}
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(block.Bytes)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(block.Bytes)
		}
	}
}

func certificatesFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certificates []*x509.Certificate
	var block *pem.Block
	rest := pemData

	for {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			certificates = append(certificates, cert)
		}
	}

	return certificates, nil
}

func toPkcs12(privateKey interface{}, cert *x509.Certificate, caCerts []*x509.Certificate, password string) ([]byte, error) {

	pkcs12Data, err := pkcs12.Encode(rand.Reader, privateKey, cert, caCerts, password)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, base64.StdEncoding.EncodedLen(len(pkcs12Data)))
	base64.StdEncoding.Encode(buf, pkcs12Data)
	return buf, nil
}
