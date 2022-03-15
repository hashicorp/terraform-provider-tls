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

		Description: "Get a public key from a PEM-encoded private key.\n\n" +
			"Use this data source to get the public key from a [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) " +
			"or [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) formatted private key, " +
			"for use in other resources.",

		Schema: map[string]*schema.Schema{
			"private_key_pem": {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				ExactlyOneOf: []string{"private_key_pem", "private_key_openssh"},
				Description: "The private key (in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format) " +
					"to extract the public key from. Currently-supported algorithms for keys are `RSA`, `ECDSA` and `ED25519`. " +
					"This is _mutually exclusive_ with `private_key_openssh`.",
			},

			"private_key_openssh": {
				Type:         schema.TypeString,
				Optional:     true,
				Sensitive:    true,
				ExactlyOneOf: []string{"private_key_pem", "private_key_openssh"},
				Description: "The private key (in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format) " +
					"to extract the public key from. Currently-supported algorithms for keys are `RSA`, `ECDSA` and `ED25519`. " +
					"This is _mutually exclusive_ with `private_key_pem`.",
			},

			"algorithm": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The name of the algorithm used by the given private key. " +
					"Possible values are: `RSA`, `ECDSA` and `ED25519`.",
			},

			"public_key_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The public key, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},

			"public_key_openssh": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The public key, in  [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format. " +
					"This is also known as ['Authorized Keys'](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. " +
					"This is populated only if the configured private key is supported: this includes all `RSA` and `ED25519` keys, as well as `ECDSA` keys " +
					"with curves `P256`, `P384` and `P521`; `ECDSA` with curve `P224` [is not supported](../../).",
			},

			"public_key_fingerprint_md5": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. " +
					"Only available if the selected private key format is compatible, as per the rules for " +
					"`public_key_openssh` and [ECDSA P224 limitations](../../).",
			},

			"public_key_fingerprint_sha256": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. " +
					"Only available if the selected private key format is compatible, as per the rules for " +
					"`public_key_openssh` and [ECDSA P224 limitations](../../).",
			},

			"id": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Unique identifier of this data source: " +
					"hexadecimal representation of the SHA1 checksum of this public key.",
			},
		},
	}
}

func readDataSourcePublicKey(d *schema.ResourceData, _ interface{}) error {
	// First, attempt to read private key from `private_key_pem` argument (PEM format)
	if prvKeyArg, ok := d.GetOk("private_key_pem"); ok {
		prvKeyPEMBytes := []byte(prvKeyArg.(string))

		prvKey, err := privateKeyFromPEM(d, prvKeyPEMBytes)
		if err != nil {
			return err
		}

		return setPublicKeyAttributes(d, prvKey)
	}

	// Second, attempt to read private key from `private_key_openssh` argument (OpenSSH PEM format)
	if prvKeyArg, ok := d.GetOk("private_key_openssh"); ok {
		prvKeyOpenSSHPEMBytes := []byte(prvKeyArg.(string))

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
