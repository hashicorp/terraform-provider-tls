package provider

import (
	"crypto"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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
					"with curves `P256`, `P384` and `P521`; `ECDSA` with curve `P224` [is not supported](../../docs#limitations).",
			},

			"public_key_fingerprint_md5": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. " +
					"Only available if the selected private key format is compatible, as per the rules for " +
					"`public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations).",
			},

			"public_key_fingerprint_sha256": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. " +
					"Only available if the selected private key format is compatible, as per the rules for " +
					"`public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations).",
			},

			"id": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Unique identifier for this data source: " +
					"hexadecimal representation of the SHA1 checksum of the data source.",
			},
		},
	}
}

func readDataSourcePublicKey(d *schema.ResourceData, _ interface{}) error {
	var prvKey crypto.PrivateKey
	var algorithm Algorithm
	var err error

	// Given the use of `ExactlyOneOf` in the Schema, we are guaranteed
	// that either `private_key_pem` or `private_key_openssh` will be set.
	if prvKeyArg, ok := d.GetOk("private_key_pem"); ok {
		prvKey, algorithm, err = parsePrivateKeyPEM([]byte(prvKeyArg.(string)))
	} else if prvKeyArg, ok := d.GetOk("private_key_openssh"); ok {
		prvKey, algorithm, err = parsePrivateKeyOpenSSHPEM([]byte(prvKeyArg.(string)))
	}
	if err != nil {
		return err
	}

	if err := d.Set("algorithm", algorithm); err != nil {
		return fmt.Errorf("error setting attribute 'algorithm = %s': %w", algorithm, err)
	}

	return setPublicKeyAttributes(d, prvKey)
}
