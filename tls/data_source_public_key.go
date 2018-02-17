package tls

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform/helper/schema"
)

func dataSourcePublicKey() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePublicKeyRead,
		Schema: map[string]*schema.Schema{
			"private_key": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PEM formatted string to use as the private key",
			},

			"private_key_path": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "File path of the PEM formatted string to use as the private key",
				ForceNew:    true,
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
	bytes := []byte(d.Get("private_key").(string))
	if len(bytes) == 0 {
		keyPath := d.Get("private_key_path").(string)
		absKeyPath, err := filepath.Abs(keyPath)
		if err != nil {
			return err
		}
		bytes, err = ioutil.ReadFile(absKeyPath)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
	}
	// decode PEM encoding to ANS.1 PKCS1 DER
	keyPemBlock, _ := pem.Decode(bytes)

	if keyPemBlock == nil || (keyPemBlock.Type != "RSA PRIVATE KEY" && keyPemBlock.Type != "EC PRIVATE KEY") {
		return fmt.Errorf("failed to decode PEM block containing RSA private key")
	}

	keyPem := string(pem.EncodeToMemory(keyPemBlock))

	// Converts an RSA private key from its ASN.1 PKCS#1 DER encoded form
	rsaKey, err := x509.ParsePKCS1PrivateKey(keyPemBlock.Bytes)
	if nil != err {
		return fmt.Errorf("error converting key to rsa %s", err)
	}

	d.Set("private_key_pem", keyPem)

	return parsePublicKey(d, rsaKey)
}
