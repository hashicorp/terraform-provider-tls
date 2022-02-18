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
	"github.com/terraform-providers/terraform-provider-tls/internal/openssh"
)

// keyGenerator extracts data from the given *schema.ResourceData,
// and generates a new public/private key-pair according to the
// selected algorithm
type keyGenerator func(d *schema.ResourceData) (crypto.PrivateKey, error)

// keyParser parses a private key from the given []byte,
// according to the selected algorithm
type keyParser func([]byte) (crypto.PrivateKey, error)

var keyGenerators = map[Algorithm]keyGenerator{
	RSA: func(d *schema.ResourceData) (crypto.PrivateKey, error) {
		rsaBits := d.Get("rsa_bits").(int)
		return rsa.GenerateKey(rand.Reader, rsaBits)
	},
	ECDSA: func(d *schema.ResourceData) (crypto.PrivateKey, error) {
		curve := d.Get("ecdsa_curve").(string)
		switch curve {
		case "P224":
			return ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		case "P256":
			return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case "P384":
			return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case "P521":
			return ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return nil, fmt.Errorf("invalid ecdsa_curve; must be P224, P256, P384 or P521")
		}
	},
	ED25519: func(d *schema.ResourceData) (crypto.PrivateKey, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key: %s", err)
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
		Create: CreatePrivateKey,
		Delete: DeletePrivateKey,
		Read:   ReadPrivateKey,

		Schema: map[string]*schema.Schema{
			"algorithm": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the algorithm to use to generate the private key",
				ForceNew:    true,
			},

			"rsa_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of bits to use when generating an RSA key",
				ForceNew:    true,
				Default:     2048,
			},

			"ecdsa_curve": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "ECDSA curve to use when generating a key",
				ForceNew:    true,
				Default:     "P224",
			},

			"private_key_pem": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
			},

			"private_key_openssh": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
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

			"public_key_fingerprint_sha256": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func CreatePrivateKey(d *schema.ResourceData, _ interface{}) error {
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

	// Marshall the Key in PEM block
	var keyPemBlock *pem.Block
	doMarshallOpenSSHKeyPemBlock := true
	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyPemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return fmt.Errorf("error encoding key to PEM: %s", err)
		}

		keyPemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: keyBytes,
		}

		// GOTCHA: `x/crypto/ssh` doesn't handle elliptic curve P-224
		if k.Curve.Params().Name == "P-224" {
			doMarshallOpenSSHKeyPemBlock = false
		}
	case *ed25519.PrivateKey:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(*k)
		if err != nil {
			return fmt.Errorf("error encoding key to PEM: %s", err)
		}

		keyPemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyBytes,
		}
	default:
		return fmt.Errorf("unsupported private key type")
	}
	d.Set("private_key_pem", string(pem.EncodeToMemory(keyPemBlock)))

	// Marshall the Key in OpenSSH PEM block, if enabled
	d.Set("private_key_openssh", "")
	if doMarshallOpenSSHKeyPemBlock {
		openSSHKeyPemBlock, err := openssh.MarshalPrivateKey(key, "")
		if err != nil {
			return err
		}
		d.Set("private_key_openssh", string(pem.EncodeToMemory(openSSHKeyPemBlock)))
	}

	return readPublicKey(d, key)
}

func DeletePrivateKey(d *schema.ResourceData, _ interface{}) error {
	d.SetId("")
	return nil
}

func ReadPrivateKey(d *schema.ResourceData, _ interface{}) error {
	return nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case *ed25519.PrivateKey:
		return k.Public()
	default:
		return nil
	}
}
