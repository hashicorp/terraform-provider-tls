package provider

import (
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourcePublicKey() *schema.Resource {
	return &schema.Resource{
		Read: dataSourcePublicKeyRead,
		Schema: map[string]*schema.Schema{
			"private_key_pem": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Sensitive:   true,
				Description: "PEM formatted string to use as the private key (provide this or ssh_server)",
			},
			"ssh_server_uri": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Sensitive:   false,
				Description: "SSH server from which to retrieve the public key (provide this or private_key_pem)",
			},
			"algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the algorithm to use to generate the private key",
			},
			"public_key_pem": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"public_key_openssh": {
				Type:     schema.TypeString,
				Computed: true,
			},
			"public_key_fingerprint_md5": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func dataSourcePublicKeyRead(d *schema.ResourceData, meta interface{}) error {
	if v, ok := d.GetOk("private_key_pem"); ok {
		// Read private key
		bytes := []byte("")
		bytes = []byte(v.(string))
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
	} else {
		// Retrieve public key from ssh server
		if v, ok := d.GetOk("ssh_server_uri"); ok {
			d.Set("algorithm", "RSA")
			return readSSHServerPublicKey(d, v.(string))
		} else {
			return fmt.Errorf("Neither private_key_pem nor ssh_server_uri provided")
		}
	}
}
