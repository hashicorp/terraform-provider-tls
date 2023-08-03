// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"golang.org/x/crypto/ssh"
)

// keyGenerator extracts data from the given *schema.ResourceData,
// and generates a new public/private key-pair according to the
// selected algorithm.
type keyGenerator func(prvKeyConf *privateKeyResourceModel) (crypto.PrivateKey, error)

// keyParser parses a private key from the given []byte,
// according to the selected algorithm.
type keyParser func([]byte) (crypto.PrivateKey, error)

var keyGenerators = map[Algorithm]keyGenerator{
	RSA: func(prvKeyConf *privateKeyResourceModel) (crypto.PrivateKey, error) {
		if prvKeyConf.RSABits.IsUnknown() || prvKeyConf.RSABits.IsNull() {
			return nil, fmt.Errorf("RSA bits curve not provided")
		}

		return rsa.GenerateKey(rand.Reader, int(prvKeyConf.RSABits.ValueInt64()))
	},
	ECDSA: func(prvKeyConf *privateKeyResourceModel) (crypto.PrivateKey, error) {
		if prvKeyConf.ECDSACurve.IsUnknown() || prvKeyConf.ECDSACurve.IsNull() {
			return nil, fmt.Errorf("ECDSA curve not provided")
		}

		curve := ECDSACurve(prvKeyConf.ECDSACurve.ValueString())
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
			return nil, fmt.Errorf("invalid ECDSA curve; supported values are: %v", supportedECDSACurves())
		}
	},
	ED25519: func(_ *privateKeyResourceModel) (crypto.PrivateKey, error) {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ED25519 key: %s", err)
		}
		return key, err
	},
}

// keyParsers provides a keyParser given a specific PEMPreamble.
var keyParsers = map[PEMPreamble]keyParser{
	PreamblePrivateKeyRSA: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParsePKCS1PrivateKey(der)
	},
	PreamblePrivateKeyEC: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParseECPrivateKey(der)
	},
	PreamblePrivateKeyPKCS8: func(der []byte) (crypto.PrivateKey, error) {
		return x509.ParsePKCS8PrivateKey(der)
	},
}

// parsePrivateKeyPEM takes a slide of bytes containing a private key
// encoded in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format,
// and returns a crypto.PrivateKey implementation, together with the Algorithm used by the key.
func parsePrivateKeyPEM(keyPEMBytes []byte) (crypto.PrivateKey, Algorithm, error) {
	pemBlock, rest := pem.Decode(keyPEMBytes)
	if pemBlock == nil {
		return nil, "", fmt.Errorf("failed to decode PEM block: decoded bytes %d, undecoded %d", len(keyPEMBytes)-len(rest), len(rest))
	}

	// Identify the PEM preamble from the block
	preamble, err := pemBlockToPEMPreamble(pemBlock)
	if err != nil {
		return nil, "", err
	}

	// Identify parser for the given PEM preamble
	parser, ok := keyParsers[preamble]
	if !ok {
		return nil, "", fmt.Errorf("unable to determine parser for PEM preamble: %s", preamble)
	}

	// Parse the specific crypto.PrivateKey from the PEM Block bytes
	prvKey, err := parser(pemBlock.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("failed to parse private key given PEM preamble '%s': %w", preamble, err)
	}

	// Identify the Algorithm of the crypto.PrivateKey
	algorithm, err := privateKeyToAlgorithm(prvKey)
	if err != nil {
		return nil, "", fmt.Errorf("failed to determine key algorithm for private key of type %T: %w", prvKey, err)
	}

	return prvKey, algorithm, nil
}

// parsePrivateKeyOpenSSHPEM takes a slide of bytes containing a private key
// encoded in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format,
// and returns a crypto.PrivateKey implementation, together with the Algorithm used by the key.
func parsePrivateKeyOpenSSHPEM(keyOpenSSHPEMBytes []byte) (crypto.PrivateKey, Algorithm, string, error) {
	prvKey, err := ssh.ParseRawPrivateKey(keyOpenSSHPEMBytes)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to parse openssh private key: %w", err)
	}

	comment, err := getPrivateKeyComment(keyOpenSSHPEMBytes)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to get private key comment: %w", err)
	}

	algorithm, err := privateKeyToAlgorithm(prvKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to determine key algorithm for private key of type %T: %w", prvKey, err)
	}
	return prvKey, algorithm, comment, nil
}

// privateKeyToPublicKey takes a crypto.PrivateKey and extracts the corresponding crypto.PublicKey,
// after having figured out its type.
func privateKeyToPublicKey(prvKey crypto.PrivateKey) (crypto.PublicKey, error) {
	signer, ok := prvKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type: %T", prvKey)
	}

	return signer.Public(), nil
}

// privateKeyToAlgorithm identifies the Algorithm used by a given crypto.PrivateKey.
func privateKeyToAlgorithm(prvKey crypto.PrivateKey) (Algorithm, error) {
	switch prvKey.(type) {
	case rsa.PrivateKey, *rsa.PrivateKey:
		return RSA, nil
	case ecdsa.PrivateKey, *ecdsa.PrivateKey:
		return ECDSA, nil
	case ed25519.PrivateKey, *ed25519.PrivateKey:
		return ED25519, nil
	default:
		return "", fmt.Errorf("unsupported private key type: %T", prvKey)
	}
}

// setPublicKeyAttributes takes a crypto.PrivateKey, extracts the corresponding crypto.PublicKey and then
// encodes related attributes on the given *tfsdk.State.
func setPublicKeyAttributes(ctx context.Context, s *tfsdk.State, prvKey crypto.PrivateKey, openSSHComment string) diag.Diagnostics {
	var diags diag.Diagnostics

	pubKey, err := privateKeyToPublicKey(prvKey)
	if err != nil {
		diags.Append(diag.NewErrorDiagnostic(
			"Failed to get public key from private key",
			err.Error(),
		))
		return diags
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		diags.Append(diag.NewErrorDiagnostic(
			"Failed to marshal public key",
			err.Error(),
		))
		return diags
	}
	pubKeyPemBlock := &pem.Block{
		Type:  PreamblePublicKey.String(),
		Bytes: pubKeyBytes,
	}

	diags.Append(s.SetAttribute(ctx, path.Root("id"), hashForState(string(pubKeyBytes)))...)
	if diags.HasError() {
		return diags
	}

	diags.Append(s.SetAttribute(ctx, path.Root("public_key_pem"), string(pem.EncodeToMemory(pubKeyPemBlock)))...)
	if diags.HasError() {
		return diags
	}

	// NOTE: ECDSA keys with elliptic curve P-224 are not supported by `x/crypto/ssh`,
	// so this will return an error: in that case, we set the below fields to empty strings
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	var pubKeySSH, pubKeySSHFingerprintMD5, pubKeySSHFingerprintSHA256 string
	if err == nil {
		sshPubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
		pubKeySSH = string(sshPubKeyBytes)

		// Manually add the comment as MarshalAuthorizedKeys ignores it: https://github.com/golang/go/issues/46870
		if openSSHComment != "" {
			pubKeySSH = fmt.Sprintf("%s %s\n", strings.TrimSuffix(pubKeySSH, "\n"), openSSHComment)
		}

		pubKeySSHFingerprintMD5 = ssh.FingerprintLegacyMD5(sshPubKey)
		pubKeySSHFingerprintSHA256 = ssh.FingerprintSHA256(sshPubKey)
	}

	diags.Append(s.SetAttribute(ctx, path.Root("public_key_openssh"), pubKeySSH)...)
	if diags.HasError() {
		return diags
	}

	diags.Append(s.SetAttribute(ctx, path.Root("public_key_fingerprint_md5"), pubKeySSHFingerprintMD5)...)
	if diags.HasError() {
		return diags
	}

	diags.Append(s.SetAttribute(ctx, path.Root("public_key_fingerprint_sha256"), pubKeySSHFingerprintSHA256)...)
	if diags.HasError() {
		return diags
	}

	return nil
}

// setPublicKeyAttributes takes a crypto.PrivateKey, extracts the corresponding crypto.PublicKey and then
// encodes related attributes on the given *tfsdk.EphemeralResultData.
func setPublicKeyAttributesEphemeral(ctx context.Context, d *tfsdk.EphemeralResultData, prvKey crypto.PrivateKey, openSSHComment string) diag.Diagnostics {
	var diags diag.Diagnostics

	pubKey, err := privateKeyToPublicKey(prvKey)
	if err != nil {
		diags.Append(diag.NewErrorDiagnostic(
			"Failed to get public key from private key",
			err.Error(),
		))
		return diags
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		diags.Append(diag.NewErrorDiagnostic(
			"Failed to marshal public key",
			err.Error(),
		))
		return diags
	}
	pubKeyPemBlock := &pem.Block{
		Type:  PreamblePublicKey.String(),
		Bytes: pubKeyBytes,
	}

	diags.Append(d.SetAttribute(ctx, path.Root("id"), hashForState(string(pubKeyBytes)))...)
	if diags.HasError() {
		return diags
	}

	diags.Append(d.SetAttribute(ctx, path.Root("public_key_pem"), string(pem.EncodeToMemory(pubKeyPemBlock)))...)
	if diags.HasError() {
		return diags
	}

	// NOTE: ECDSA keys with elliptic curve P-224 are not supported by `x/crypto/ssh`,
	// so this will return an error: in that case, we set the below fields to empty strings
	sshPubKey, err := ssh.NewPublicKey(pubKey)
	var pubKeySSH, pubKeySSHFingerprintMD5, pubKeySSHFingerprintSHA256 string
	if err == nil {
		sshPubKeyBytes := ssh.MarshalAuthorizedKey(sshPubKey)
		pubKeySSH = string(sshPubKeyBytes)

		// Manually add the comment as MarshalAuthorizedKeys ignores it: https://github.com/golang/go/issues/46870
		if openSSHComment != "" {
			pubKeySSH = fmt.Sprintf("%s %s\n", strings.TrimSuffix(pubKeySSH, "\n"), openSSHComment)
		}

		pubKeySSHFingerprintMD5 = ssh.FingerprintLegacyMD5(sshPubKey)
		pubKeySSHFingerprintSHA256 = ssh.FingerprintSHA256(sshPubKey)
	}

	diags.Append(d.SetAttribute(ctx, path.Root("public_key_openssh"), pubKeySSH)...)
	if diags.HasError() {
		return diags
	}

	diags.Append(d.SetAttribute(ctx, path.Root("public_key_fingerprint_md5"), pubKeySSHFingerprintMD5)...)
	if diags.HasError() {
		return diags
	}

	diags.Append(d.SetAttribute(ctx, path.Root("public_key_fingerprint_sha256"), pubKeySSHFingerprintSHA256)...)
	if diags.HasError() {
		return diags
	}

	return nil
}

// Note: The SSH package does not currently expose the comment in the private key, so an adapted version of
// parseOpenSSHPrivateKey from https://github.com/golang/crypto/blob/master/ssh/keys.go#L1532
const privateKeyAuthMagic = "openssh-key-v1\x00"

type openSSHEncryptedPrivateKey struct {
	CipherName   string
	KdfName      string
	KdfOpts      string
	NumKeys      uint32
	PubKey       []byte
	PrivKeyBlock []byte
}

type openSSHPrivateKey struct {
	Check1  uint32
	Check2  uint32
	Keytype string
	Rest    []byte `ssh:"rest"`
}

type openSSHRSAPrivateKey struct {
	N       *big.Int
	E       *big.Int
	D       *big.Int
	Iqmp    *big.Int
	P       *big.Int
	Q       *big.Int
	Comment string
	Pad     []byte `ssh:"rest"`
}

type openSSHEd25519PrivateKey struct {
	Pub     []byte
	Priv    []byte
	Comment string
	Pad     []byte `ssh:"rest"`
}

type openSSHECDSAPrivateKey struct {
	Curve   string
	Pub     []byte
	D       *big.Int
	Comment string
	Pad     []byte `ssh:"rest"`
}

func getPrivateKeyComment(pemBytes []byte) (string, error) {
	block, _ := pem.Decode(pemBytes)

	if block == nil {
		return "", errors.New("ssh: no key found")
	}

	key := block.Bytes

	if len(key) < len(privateKeyAuthMagic) || string(key[:len(privateKeyAuthMagic)]) != privateKeyAuthMagic {
		return "", errors.New("ssh: invalid openssh private key format")
	}
	remaining := key[len(privateKeyAuthMagic):]

	var w openSSHEncryptedPrivateKey
	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return "", err
	}
	if w.NumKeys != 1 {
		// We only support single key files, and so does OpenSSH.
		// https://github.com/openssh/openssh-portable/blob/4103a3ec7/sshkey.c#L4171
		return "", errors.New("ssh: multi-key files are not supported")
	}

	var pk1 openSSHPrivateKey
	if err := ssh.Unmarshal(w.PrivKeyBlock, &pk1); err != nil || pk1.Check1 != pk1.Check2 {
		if w.CipherName != "none" {
			return "", x509.IncorrectPasswordError
		}
		return "", errors.New("ssh: malformed OpenSSH key")
	}

	switch pk1.Keytype {
	case ssh.KeyAlgoRSA:
		var key openSSHRSAPrivateKey
		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return "", err
		}

		return key.Comment, nil
	case ssh.KeyAlgoED25519:
		var key openSSHEd25519PrivateKey
		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return "", err
		}
		return key.Comment, nil
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		var key openSSHECDSAPrivateKey
		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return "", err
		}
		return key.Comment, nil
	default:
		return "", errors.New("ssh: unhandled key type")
	}
}
