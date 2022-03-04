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
	"io/ioutil"

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
		Create: CreatePrivateKey,
		Delete: DeletePrivateKey,
		Read:   ReadPrivateKey,
		Importer: &schema.ResourceImporter{
			State: importKey,
		},

		Schema: map[string]*schema.Schema{
			"algorithm": {
				Type:             schema.TypeString,
				Required:         true,
				Description:      "Name of the algorithm to use to generate the private key",
				ForceNew:         true,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice(SupportedAlgorithmsStr(), false)),
			},

			"rsa_bits": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Number of bits to use when generating an RSA key",
				ForceNew:    true,
				Default:     2048,
			},

			"ecdsa_curve": {
				Type:             schema.TypeString,
				Optional:         true,
				Description:      "Curve to use when generating an ECDSA key",
				ForceNew:         true,
				Default:          P224,
				ValidateDiagFunc: validation.ToDiagFunc(validation.StringInSlice(SupportedECDSACurvesStr(), false)),
			},

			"private_key_pem": {
				Type:        schema.TypeString,
				Description: "Private key data in PEM format",
				Computed:    true,
				Sensitive:   true,
			},

			"private_key_openssh": {
				Type:        schema.TypeString,
				Description: "Private key data in OpenSSH-compatible PEM format",
				Computed:    true,
				Sensitive:   true,
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

	// Marshal the Key in PEM block
	var keyPemBlock *pem.Block
	doMarshalOpenSSHKeyPemBlock := true
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
			doMarshalOpenSSHKeyPemBlock = false
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

	return readPublicKey(d, key)
}

func DeletePrivateKey(d *schema.ResourceData, _ interface{}) error {
	d.SetId("")
	return nil
}

func ReadPrivateKey(_ *schema.ResourceData, _ interface{}) error {
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

func importKey(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
	path := d.Id()
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %w", err)
	}
	keyPemBlock, _ := pem.Decode(bytes)

	if keyPemBlock == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	keyAlgo := ""
	switch keyPemBlock.Type {
	case "RSA PRIVATE KEY":
		keyAlgo = "RSA"
	case "EC PRIVATE KEY":
		keyAlgo = "ECDSA"
	default:
		return nil, fmt.Errorf("private key of type unknown type")
	}
	d.Set("algorithm", keyAlgo)
	d.Set("private_key_pem", string(pem.EncodeToMemory(keyPemBlock)))

	key, err := parsePrivateKey(d, "private_key_pem", "algorithm")
	if err != nil {
		return nil, fmt.Errorf("error converting key to algo: %s - %s", keyAlgo, err)
	}
	err = readPublicKey(d, key)
	if err != nil {
		return nil, fmt.Errorf("error reading public key: %w", err)
	}

	return []*schema.ResourceData{d}, nil
}
