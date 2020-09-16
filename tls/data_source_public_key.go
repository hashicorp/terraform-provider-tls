package tls

import (
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func dataSourcePublicKey() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePublicKeyRead,
		Schema: map[string]*schema.Schema{
			"private_key_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "(Unencrypted) PEM formatted private key",
			},
			"algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the algorithm used to generate the private key",
			},
			"public_key_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Public Key as X.509 SubjectPublicKeyInfo in ASN.1/DER, in PEM (base64) wrapper",
			},
			"public_key_b16": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Public Key as X.509 SubjectPublicKeyInfo in ASN.1/DER, hex (base16) encoded",
			},
			"public_key_openssh": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Public Key as OpenSSH XDR-like SSH wire format, (in base64)",
			},
			"public_key_fingerprint_md5": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The (OpenSSH) Public Key's fingerprint as described by RFC 4716 § 4.",
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
		typ := "unknown"

		if keyPemBlock != nil {
			typ = keyPemBlock.Type
		}

		return fmt.Errorf("failed to decode PEM block containing private key of type %#v", typ)
	}

	keyAlgo := ""
	switch keyPemBlock.Type {
	case "RSA PRIVATE KEY":
		keyAlgo = "RSA"
	case "EC PRIVATE KEY":
		keyAlgo = "ECDSA"
	}
	d.Set("algorithm", keyAlgo)
	// Converts a private key from its ASN.1 PKCS#1 DER encoded form
	key, err := parsePrivateKey(d, "private_key_pem", "algorithm")
	if err != nil {
		return fmt.Errorf("error converting key to algo: %s - %s", keyAlgo, err)
	}

	return readPublicKey(d, key)
}
