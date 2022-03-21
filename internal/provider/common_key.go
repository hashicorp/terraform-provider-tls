package provider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"golang.org/x/crypto/ssh"
)

// parsePrivateKeyPEM takes a slide of bytes containing a private key
// encoded in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format,
// and returns a crypto.PrivateKey implementation, together with the Algorithm used by the key.
func parsePrivateKeyPEM(keyPEMBytes []byte) (crypto.PrivateKey, Algorithm, error) {
	pemBlock, rest := pem.Decode(keyPEMBytes)
	if pemBlock == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block: decoded bytes %d, undecoded %d", len(keyPEMBytes)-len(rest), len(rest))
	}

	// Map PEM Preamble of the Private Key to the corresponding Algorithm
	algorithm, err := PEMPreamblePrivateKey(pemBlock.Type).Algorithm()
	if err != nil {
		return nil, "", err
	}

	// Identify parser for the given key, using the Algorithm
	parser, ok := keyParsers[algorithm]
	if !ok {
		return nil, "", fmt.Errorf("unsupported key algorithm: %s", algorithm)
	}

	// Parse the specific crypto.PrivateKey from the PEM Block bytes
	prvKey, err := parser(pemBlock.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse private key of algorithm %s: %w", algorithm, err)
	}

	return prvKey, algorithm, nil
}

// parsePrivateKeyOpenSSHPEM takes a slide of bytes containing a private key
// encoded in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format,
// and returns a crypto.PrivateKey implementation, together with the Algorithm used by the key.
func parsePrivateKeyOpenSSHPEM(keyOpenSSHPEMBytes []byte) (crypto.PrivateKey, Algorithm, error) {
	prvKey, err := ssh.ParseRawPrivateKey(keyOpenSSHPEMBytes)
	if err != nil {
		return nil, "", err
	}

	algorithm, err := privateKeyToAlgorithm(prvKey)
	if err != nil {
		return nil, "", err
	}

	return prvKey, algorithm, nil
}

// privateKeyToPublicKey takes a crypto.PrivateKey and extracts the corresponding crypto.PublicKey,
// after having figured out its type.
func privateKeyToPublicKey(prvKey crypto.PrivateKey) crypto.PublicKey {
	switch k := prvKey.(type) {
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

// privateKeyToAlgorithm identifies the Algorithm used by a given crypto.PrivateKey.
func privateKeyToAlgorithm(prvKey crypto.PrivateKey) (Algorithm, error) {
	switch k := prvKey.(type) {
	case *rsa.PrivateKey:
		return RSA, nil
	case *ecdsa.PrivateKey:
		return ECDSA, nil
	case *ed25519.PrivateKey:
		return ED25519, nil
	default:
		return "", fmt.Errorf("failed to identify key algorithm for unsupported private key: %#v", k)
	}
}

// setPublicKeyAttributes takes a crypto.PrivateKey, extracts the corresponding crypto.PublicKey and then
// encodes related attributes on the given schema.ResourceData.
func setPublicKeyAttributes(d *schema.ResourceData, prvKey crypto.PrivateKey) error {
	pubKey := privateKeyToPublicKey(prvKey)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key error: %s", err)
	}
	pubKeyPemBlock := &pem.Block{
		Type:  PublicKey.String(),
		Bytes: pubKeyBytes,
	}

	d.SetId(hashForState(string(pubKeyBytes)))

	if err := d.Set("public_key_pem", string(pem.EncodeToMemory(pubKeyPemBlock))); err != nil {
		return fmt.Errorf("error setting value on key 'public_key_pem': %s", err)
	}

	// NOTE: ECDSA keys with elliptic curve P-224 are not supported by `x/crypto/ssh`,
	// so this will return an error: in that case, we set the below fields to emptry strings
	sshPubKey, err := ssh.NewPublicKey(privateKeyToPublicKey(prvKey))
	var pubKeySSH, pubKeySSHFingerprintMD5, pubKeySSHFingerprintSHA256 string
	if err == nil {
		sshPubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)

		pubKeySSH = string(sshPubKeyBytes)
		pubKeySSHFingerprintMD5 = ssh.FingerprintLegacyMD5(sshPubKey)
		pubKeySSHFingerprintSHA256 = ssh.FingerprintSHA256(sshPubKey)
	}

	if err := d.Set("public_key_openssh", pubKeySSH); err != nil {
		return fmt.Errorf("error setting value on key 'public_key_openssh': %s", err)
	}

	if err := d.Set("public_key_fingerprint_md5", pubKeySSHFingerprintMD5); err != nil {
		return fmt.Errorf("error setting value on key 'public_key_fingerprint_md5': %s", err)
	}

	if err := d.Set("public_key_fingerprint_sha256", pubKeySSHFingerprintSHA256); err != nil {
		return fmt.Errorf("error setting value on key 'public_key_fingerprint_sha256': %s", err)
	}

	return nil
}
