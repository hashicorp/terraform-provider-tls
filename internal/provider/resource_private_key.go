package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/terraform-providers/terraform-provider-tls/internal/openssh"
)

// keyGenerator extracts data from the given *schema.ResourceData,
// and generates a new public/private key-pair according to the
// selected algorithm.
type keyGenerator func(d *schema.ResourceData) (crypto.PrivateKey, error)

// keyParser parses a private key from the given []byte,
// according to the selected algorithm.
type keyParser func([]byte) (crypto.PrivateKey, error)

var keyGenerators = map[Algorithm]keyGenerator{
	RSA: func(d *schema.ResourceData) (crypto.PrivateKey, error) {
		rsaBits := d.Get("rsa_bits").(int)
		return rsa.GenerateKey(rand.Reader, rsaBits)
	},
	ECDSA: func(d *schema.ResourceData) (crypto.PrivateKey, error) {
		curve := ECDSACurve(d.Get("ecdsa_curve").(string))
		switch curve {
		case P224:
			return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case P256:
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case P384:
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case P521:
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, fmt.Errorf("invalid ECDSA curve; supported values are: %v", SupportedECDSACurves())
		}
	},
	ED25519: func(d *schema.ResourceData) (crypto.PrivateKey, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ED25519 key: %s", err)
		}
		return &key, err
	},
}

var keyParsers = map[Algorithm]keyParser{
	RSA: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParsePKCS1PrivateKey(der)
	},
	ECDSA: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParseECPrivateKey(der)
	},
	ED25519: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParsePKCS8PrivateKey(der)
	},
}

func resourcePrivateKey() *schema.Resource {
	return &schema.Resource{
		Create: createResourcePrivateKey,
		Delete: deleteResourcePrivateKey,
		Read:   readResourcePrivateKey,

		Description: "Creates a PEM (and OpenSSH) formatted private key.\n\n" +
			"Generates a secure private key and encodes it in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) and " +
			"[OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) formats. " +
			"This resource is primarily intended for easily bootstrapping throwaway development environments.",

		Schema: map[string]*schema.Schema{
			"algorithm": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice(SupportedAlgorithmsStr(), false)),
				Description: "Name of the algorithm to use when generating the private key. " +
					"Currently-supported values are `RSA`, `ECDSA` and `ED25519`.",
			},

			"rsa_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				ForceNew:    true,
				Default:     2048,
				Description: "When `algorithm` is `RSA`, the size of the generated RSA key, in bits (default: `2048`).",
			},

			"ecdsa_curve": {
				Type:             schema.TypeString,
				Optional:         true,
				ForceNew:         true,
				Default:          P224,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice(SupportedECDSACurvesStr(), false)),
				Description: "When `algorithm` is `ECDSA`, the name of the elliptic curve to use. " +
					"Currently-supported values are `P224`, `P256`, `P384` or `P521` (default: `P224`).",
			},

			"private_key_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Private key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},

			"private_key_openssh": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "Private key data in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format.",
			},

			"public_key_pem": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Public key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},

			"public_key_openssh": {
				Type:     schema.TypeString,
				Computed: true,
				Description: " The public key data in " +
					"[\"Authorized Keys\"](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. " +
					"This is populated only if the configured private key is supported: " +
					"this includes all `RSA` and `ED25519` keys, as well as `ECDSA` keys with curves " +
					"`P256`, `P384` and `P521`. `ECDSA` with curve `P224` [is not supported](../../#limitations).",
			},

			"public_key_fingerprint_md5": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../#limitations).",
			},

			"public_key_fingerprint_sha256": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../#limitations).",
			},

			"id": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "Unique identifier for this resource: " +
					"hexadecimal representation of the SHA1 checksum of the resource.",
			},
		},
	}
}

func createResourcePrivateKey(d *schema.ResourceData, _ interface{}) error {
	keyAlgoName := Algorithm(d.Get("algorithm").(string))

	// Identify the correct (Private) Key Generator
	var keyGen keyGenerator
	var ok bool
	if keyGen, ok = keyGenerators[keyAlgoName]; !ok {
		return fmt.Errorf("invalid key_algorithm %#v", keyAlgoName)
	}

	// Generate the new Key
	key, err := keyGen(d)
	if err != nil {
		return err
	}

	// Marshal the Key in PEM block
	var keyPemBlock *pem.Block
	doMarshalOpenSSHKeyPemBlock := true
	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyPemBlock = &pem.Block{
			Type:  PrivateKeyRSA.String(),
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return fmt.Errorf("error encoding key to PEM: %s", err)
		}

		keyPemBlock = &pem.Block{
			Type:  PrivateKeyECDSA.String(),
			Bytes: keyBytes,
		}

		// GOTCHA: `x/crypto/ssh` doesn't handle elliptic curve P-224
		if k.Curve.Params().Name == "P-224" {
			doMarshalOpenSSHKeyPemBlock = false
		}
	case *ed25519.PrivateKey:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(*k)
		if err != nil {
			return fmt.Errorf("error encoding key to PEM: %s", err)
		}

		keyPemBlock = &pem.Block{
			Type:  PrivateKeyED25519.String(),
			Bytes: keyBytes,
		}
	default:
		return fmt.Errorf("unsupported private key type")
	}

	if err := d.Set("private_key_pem", string(pem.EncodeToMemory(keyPemBlock))); err != nil {
		return fmt.Errorf("error setting value on key 'private_key_pem': %s", err)
	}

	// Marshal the Key in OpenSSH PEM block, if enabled
	prvKeyOpenSSH := ""
	if doMarshalOpenSSHKeyPemBlock {
		openSSHKeyPemBlock, err := openssh.MarshalPrivateKey(key, "")
		if err != nil {
			return fmt.Errorf("unable to marshal private key into OpenSSH format: %w", err)
		}

		prvKeyOpenSSH = string(pem.EncodeToMemory(openSSHKeyPemBlock))
	}
	if err := d.Set("private_key_openssh", prvKeyOpenSSH); err != nil {
		return fmt.Errorf("error setting value on key 'private_key_openssh': %s", err)
	}

	return setPublicKeyAttributes(d, key)
}

func deleteResourcePrivateKey(d *schema.ResourceData, _ interface{}) error {
	d.SetId("")
	return nil
}

func readResourcePrivateKey(_ *schema.ResourceData, _ interface{}) error {
	return nil
}
