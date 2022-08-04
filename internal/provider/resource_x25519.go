package provider

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/curve25519"
)

func resourceX25519() *schema.Resource {
	return &schema.Resource{
		Create: CreateKeyPair,
		Delete: DeleteKeyPair,
		Read:   ReadKeyPair,

		Schema: map[string]*schema.Schema{
			"private_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: true,
				Default:   nil,
			},

			"public_key": {
				Type:      schema.TypeString,
				Computed:  true,
				Sensitive: false,
				Default:   nil,
			},
		},
	}
}

func CreateKeyPair(d *schema.ResourceData, meta interface{}) error {
	key := make([]byte, curve25519.ScalarSize)

	_, err := rand.Read(key)
	if err != nil {
		return fmt.Errorf("failed to generate x25519 private key: %s", err)
	}

	publicKey, _ := curve25519.X25519(key, curve25519.Basepoint)

	d.SetId(hashForState(string((publicKey))))
	d.Set("private_key", base64.StdEncoding.EncodeToString([]byte(key)))
	d.Set("public_key", base64.StdEncoding.EncodeToString([]byte(publicKey)))

	return nil
}

func DeleteKeyPair(d *schema.ResourceData, meta interface{}) error {
	d.SetId("")
	return nil
}

func ReadKeyPair(d *schema.ResourceData, meta interface{}) error {
	return nil
}
