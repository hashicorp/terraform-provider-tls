package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/terraform-providers/terraform-provider-tls/internal/openssh"
)

func resourcePrivateKey() *schema.Resource {
	return &schema.Resource{
		CreateContext: createResourcePrivateKey,
		DeleteContext: deleteResourcePrivateKey,
		ReadContext:   readResourcePrivateKey,

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
				Type:     schema.TypeString,
				Computed: true,
				Description: "Public key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},

			"public_key_openssh": {
				Type:     schema.TypeString,
				Computed: true,
				Description: " The public key data in " +
					"[\"Authorized Keys\"](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. " +
					"This is populated only if the configured private key is supported: " +
					"this includes all `RSA` and `ED25519` keys, as well as `ECDSA` keys with curves " +
					"`P256`, `P384` and `P521`. `ECDSA` with curve `P224` [is not supported](../../docs#limitations). " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},

			"public_key_fingerprint_md5": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations).",
			},

			"public_key_fingerprint_sha256": {
				Type:     schema.TypeString,
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations).",
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

func createResourcePrivateKey(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	keyAlgoName := Algorithm(d.Get("algorithm").(string))

	// Identify the correct (Private) Key Generator
	var keyGen keyGenerator
	var ok bool
	if keyGen, ok = keyGenerators[keyAlgoName]; !ok {
		return diag.Errorf("invalid key_algorithm %#v", keyAlgoName)
	}

	// Generate the new Key
	key, err := keyGen(d)
	if err != nil {
		return diag.FromErr(err)
	}

	// Marshal the Key in PEM block
	var keyPemBlock *pem.Block
	doMarshalOpenSSHKeyPemBlock := true
	switch k := key.(type) {
	case *rsa.PrivateKey:
		keyPemBlock = &pem.Block{
			Type:  PreamblePrivateKeyRSA.String(),
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return diag.Errorf("error encoding key to PEM: %s", err)
		}

		keyPemBlock = &pem.Block{
			Type:  PreamblePrivateKeyEC.String(),
			Bytes: keyBytes,
		}

		// GOTCHA: `x/crypto/ssh` doesn't handle elliptic curve P-224
		if k.Curve.Params().Name == "P-224" {
			doMarshalOpenSSHKeyPemBlock = false
		}
	case ed25519.PrivateKey:
		keyBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			return diag.Errorf("error encoding key to PEM: %s", err)
		}

		keyPemBlock = &pem.Block{
			Type:  PreamblePrivateKeyPKCS8.String(),
			Bytes: keyBytes,
		}
	default:
		return diag.Errorf("unsupported private key type")
	}

	if err := d.Set("private_key_pem", string(pem.EncodeToMemory(keyPemBlock))); err != nil {
		return diag.Errorf("error setting value on key 'private_key_pem': %s", err)
	}

	// Marshal the Key in OpenSSH PEM block, if enabled
	prvKeyOpenSSH := ""
	if doMarshalOpenSSHKeyPemBlock {
		openSSHKeyPemBlock, err := openssh.MarshalPrivateKey(key, "")
		if err != nil {
			return diag.Errorf("unable to marshal private key into OpenSSH format: %v", err)
		}

		prvKeyOpenSSH = string(pem.EncodeToMemory(openSSHKeyPemBlock))
	}
	if err := d.Set("private_key_openssh", prvKeyOpenSSH); err != nil {
		return diag.Errorf("error setting value on key 'private_key_openssh': %s", err)
	}

	return setPublicKeyAttributes(d, key)
}

func deleteResourcePrivateKey(_ context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

func readResourcePrivateKey(_ context.Context, _ *schema.ResourceData, _ interface{}) diag.Diagnostics {
	return nil
}
