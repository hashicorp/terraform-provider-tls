package tls

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/terraform/helper/schema"
)

func resourcePublicKey() *schema.Resource {
	return &schema.Resource{
		Create: CreatePublicKey,
		Delete: DeletePublicKey,
		Read:   ReadPublicKey,

		Schema: map[string]*schema.Schema{
			"private_key": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "PEM formatted string to use as the private key",
				ForceNew:    true,
			},

			"private_key_path": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				Description: "File path of the PEM formatted string to use as the private key",
				ForceNew:    true,
			},

			"private_key_pem": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
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

func CreatePublicKey(d *schema.ResourceData, meta interface{}) error {
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

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey(rsaKey))
	if err != nil {
		return fmt.Errorf("failed to marshal public key error: %s", err)
	}
	pubKeyPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	d.SetId(hashForState(string((pubKeyBytes))))
	d.Set("private_key_pem", keyPem)
	d.Set("public_key_pem", string(pem.EncodeToMemory(pubKeyPemBlock)))

	sshPubKey, err := ssh.NewPublicKey(publicKey(rsaKey))
	if err == nil {
		// Not all EC types can be SSH keys, so we'll produce this only
		// if an appropriate type was selected.
		sshPubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
		d.Set("public_key_openssh", string(sshPubKeyBytes))
	} else {
		d.Set("public_key_openssh", "")
	}

	return nil
}

func DeletePublicKey(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func ReadPublicKey(d *schema.ResourceData, meta interface{}) error {
	return nil
}

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}
