package provider

import (
	"crypto"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func dataSourcePublicKey() *schema.Resource {
	return &schema.Resource{
		Read: readDataSourcePublicKey,
		Schema: map[string]*schema.Schema{
			"private_key_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Private key data in PEM format; either this or `private_key_openssh` must be set",
			},

			"private_key_openssh": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Private key data in OpenSSH-compatible PEM format; either this or `private_key_pem` must be set",
			},

			"algorithm": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Name of the algorithm used to generate the private key",
			},

			"public_key_pem": {
				Type:        schema.TypeString,
				Description: "Public key data in PEM format",
				Computed:    true,
			},

			"public_key_openssh": {
				Type:        schema.TypeString,
				Description: "Public key data in OpenSSH-compatible PEM format",
				Computed:    true,
			},

			"public_key_fingerprint_md5": {
				Type:        schema.TypeString,
				Description: "Fingerprint of the public key data in OpenSSH MD5 hash format",
				Computed:    true,
			},

			"public_key_fingerprint_sha256": {
				Type:        schema.TypeString,
				Description: "Fingerprint of the public key data in OpenSSH SHA256 hash format",
				Computed:    true,
			},
		},
	}
}

func readDataSourcePublicKey(d *schema.ResourceData, _ interface{}) error {
	prvKeyPEMArg, prvKeyPEMArgOK := d.GetOk("private_key_pem")
	prvKeyOpenSSHPEMArg, prvKeyOpenSSHPEMArgOK := d.GetOk("private_key_openssh")

	// Confirm that not both ways to provide a private key were used at the same time
	if prvKeyPEMArgOK && prvKeyOpenSSHPEMArgOK {
		return fmt.Errorf("either provide private key via `private_key_pem` or `private_key_openssh`, not both")
	}

	// First, attempt to read private key from `private_key_pem` argument (PEM format)
	if prvKeyPEMArgOK {
		prvKeyPEMBytes := []byte(prvKeyPEMArg.(string))

		prvKey, err := privateKeyFromPEM(d, prvKeyPEMBytes)
		if err != nil {
			return err
		}

		return setPublicKeyAttributes(d, prvKey)
	}

	// Second, attempt to read private key from `private_key_openssh` argument (OpenSSH PEM format)
	if prvKeyOpenSSHPEMArgOK {
		prvKeyOpenSSHPEMBytes := []byte(prvKeyOpenSSHPEMArg.(string))

		prvKey, err := ssh.ParseRawPrivateKey(prvKeyOpenSSHPEMBytes)
		if err != nil {
			return err
		}

		keyAlgorithm, err := PrivateKeyToAlgorithm(prvKey)
		if err != nil {
			return err
		}
		if err := d.Set("algorithm", keyAlgorithm); err != nil {
			return fmt.Errorf("error setting value on key 'algorithm': %s", err)
		}

		return setPublicKeyAttributes(d, prvKey)
	}

	return fmt.Errorf("no valid private key was provided via `private_key_pem` nor `private_key_openssh`")
}

func privateKeyFromPEM(d *schema.ResourceData, prvKeyPEMBytes []byte) (crypto.PrivateKey, error) {
	// decode raw PEM bytes to the corresponding pem.Block encoded structure (ANS.1 PKCS1 DER)
	keyPemBlock, keyRest := pem.Decode(prvKeyPEMBytes)
	if keyPemBlock == nil {
		keyRestLen := len(keyRest)
		keyDecodedLen := len(prvKeyPEMBytes) - keyRestLen
		return nil, fmt.Errorf("failed to decode raw PEM block: decoded bytes %d, undecoded %d", keyDecodedLen, keyRestLen)
	}

	// Map PEM Preamble of the Private Key to the corresponding Algorithm
	keyAlgorithm, err := PEMPreamblePrivateKey(keyPemBlock.Type).Algorithm()
	if err != nil {
		return nil, err
	}

	if err := d.Set("algorithm", keyAlgorithm); err != nil {
		return nil, fmt.Errorf("error setting value on key 'algorithm': %s", err)
	}

	// Converts a private key from its ASN.1 PKCS#1 DER encoded form
	prvKey, err := parsePrivateKey(d, "private_key_pem", "algorithm")
	if err != nil {
		return nil, fmt.Errorf("error converting key to algo: %s - %s", keyAlgorithm, err)
	}
	return prvKey, nil
}
