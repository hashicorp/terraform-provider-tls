package tls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourcePublicKey() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePublicKeyRead,
		Schema: map[string]*schema.Schema{
			"private_key_pem": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				Description: "PEM formatted string to use as the private key",
			},
			"public_key_pem": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
			"public_key_openssh": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourcePublicKeyRead(d *schema.ResourceData, meta interface{}) error {
	// Read private key
	bytes := []byte("")
	if v, ok := d.GetOk("private_key_pem"); ok {
		bytes = []byte(v.(string))
	} else {
		return fmt.Errorf("invalid private key %#v", v)
	}
	// decode PEM encoding to ANS.1 PKCS1 DER
	keyPemBlock, _ := pem.Decode(bytes)

	if keyPemBlock == nil || (keyPemBlock.Type != "RSA PRIVATE KEY" && keyPemBlock.Type != "EC PRIVATE KEY") {
		return fmt.Errorf("failed to decode PEM block containing private key of type %#v", keyPemBlock.Type)
	}

	keyPem := string(pem.EncodeToMemory(keyPemBlock))

	// Converts an RSA private key from its ASN.1 PKCS#1 DER encoded form
	rsaKey, err := x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
	if nil != err {
		return fmt.Errorf("error converting key to rsa %s", err)
	}

	d.Set("private_key_pem", keyPem)

	return readPublicKey(d, rsaKey)
}
