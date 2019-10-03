package provider

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/rand"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

func decodePEM(d *schema.ResourceData, pemKey, pemType string) (*pem.Block, error) {
	block, _ := pem.Decode([]byte(d.Get(pemKey).(string)))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", pemKey)
	}
	if pemType != "" && block.Type != pemType {
		return nil, fmt.Errorf("invalid PEM type in %s: %s", pemKey, block.Type)
	}

	return block, nil
}

func parsePrivateKey(d *schema.ResourceData, pemKey, algoKey string) (interface{}, error) {
	algoName := d.Get(algoKey).(string)

	keyFunc, ok := keyParsers[algoName]
	if !ok {
		return nil, fmt.Errorf("invalid %s: %#v", algoKey, algoName)
	}

	block, err := decodePEM(d, pemKey, "")
	if err != nil {
		return nil, err
	}

	key, err := keyFunc(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decode %s: %s", pemKey, err)
	}

	return key, nil
}

func parseCertificate(d *schema.ResourceData, pemKey string) (*x509.Certificate, error) {
	block, err := decodePEM(d, pemKey, "")
	if err != nil {
		return nil, err
	}

	certs, err := x509.ParseCertificates(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %s", pemKey, err)
	}
	if len(certs) < 1 {
		return nil, fmt.Errorf("no certificates found in %s", pemKey)
	}
	if len(certs) > 1 {
		return nil, fmt.Errorf("multiple certificates found in %s", pemKey)
	}

	return certs[0], nil
}

func parseCertificateRequest(d *schema.ResourceData, pemKey string) (*x509.CertificateRequest, error) {
	block, err := decodePEM(d, pemKey, pemCertReqType)
	if err != nil {
		return nil, err
	}

	certReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %s", pemKey, err)
	}

	return certReq, nil
}

func readPublicKey(d *schema.ResourceData, rsaKey interface{}) error {
	pubKey := publicKey(rsaKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key error: %s", err)
	}
	pubKeyPemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	d.SetId(hashForState(string((pubKeyBytes))))
	d.Set("public_key_pem", string(pem.EncodeToMemory(pubKeyPemBlock)))

	sshPubKey, err := ssh.NewPublicKey(publicKey(rsaKey))
	if err == nil {
		// Not all EC types can be SSH keys, so we'll produce this only
		// if an appropriate type was selected.
		sshPubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
		d.Set("public_key_openssh", string(sshPubKeyBytes))
		d.Set("public_key_fingerprint_md5", ssh.FingerprintLegacyMD5(sshPubKey))
	} else {
		d.Set("public_key_openssh", "")
		d.Set("public_key_fingerprint_md5", "")
	}
	return nil
}

// From https://github.com/mikesmitty/edkey/blob/master/edkey.go
//
// Writes ed25519 private keys into the new OpenSSH private key format.
// I have no idea why this isn't implemented anywhere yet, you can do seemingly
// everything except write it to disk in the OpenSSH private key format.
func marshalED25519PrivateKey(key ed25519.PrivateKey) []byte {
	// Add our key header (followed by a null byte)
	magic := append([]byte("openssh-key-v1"), 0)

	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}

	// Fill out the private key fields
	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Pub     []byte
		Priv    []byte
		Comment string
		Pad     []byte `ssh:"rest"`
	}{}

	// Set our check ints
	ci := rand.Uint32()
	pk1.Check1 = ci
	pk1.Check2 = ci

	// Set our key type
	pk1.Keytype = ssh.KeyAlgoED25519

	// Add the pubkey to the optionally-encrypted block
	pk, ok := key.Public().(ed25519.PublicKey)
	if !ok {
		//fmt.Fprintln(os.Stderr, "ed25519.PublicKey type assertion failed on an ed25519 public key. This should never ever happen.")
		return nil
	}
	pubKey := []byte(pk)
	pk1.Pub = pubKey

	// Add our private key
	pk1.Priv = []byte(key)

	// Might be useful to put something in here at some point
	pk1.Comment = ""

	// Add some padding to match the encryption block size within PrivKeyBlock (without Pad field)
	// 8 doesn't match the documentation, but that's what ssh-keygen uses for unencrypted keys. *shrug*
	bs := 8
	blockLen := len(ssh.Marshal(pk1))
	padLen := (bs - (blockLen % bs)) % bs
	pk1.Pad = make([]byte, padLen)

	// Padding is a sequence of bytes like: 1, 2, 3...
	for i := 0; i < padLen; i++ {
		pk1.Pad[i] = byte(i + 1)
	}

	// Generate the pubkey prefix "\0\0\0\nssh-ed25519\0\0\0 "
	prefix := []byte{0x0, 0x0, 0x0, 0x0b}
	prefix = append(prefix, []byte(ssh.KeyAlgoED25519)...)
	prefix = append(prefix, []byte{0x0, 0x0, 0x0, 0x20}...)

	// Only going to support unencrypted keys for now
	w.CipherName = "none"
	w.KdfName = "none"
	w.KdfOpts = ""
	w.NumKeys = 1
	w.PubKey = append(prefix, pubKey...)
	w.PrivKeyBlock = ssh.Marshal(pk1)

	magic = append(magic, ssh.Marshal(w)...)

	return magic
}
