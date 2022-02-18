package openssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"golang.org/x/crypto/ssh"
	"testing"

	testifyAssert "github.com/stretchr/testify/assert"
)

func TestOpenSSHFormat_MarshalAndUnmarshall_RSA(t *testing.T) {
	assert := testifyAssert.New(t)

	// Given an RSA private key
	rsaOrig, err := rsa.GenerateKey(rand.Reader, 4096)
	assert.NoError(err)

	// Marshall it to OpenSSH PEM format
	pemOpenSSHPrvKey, err := MarshalPrivateKey(rsaOrig, "")
	assert.NoError(err)
	pemOpenSSHPrvKeyBytes := pem.EncodeToMemory(pemOpenSSHPrvKey)

	// Parse it back into an RSA private key
	rawPrivateKey, err := ssh.ParseRawPrivateKey(pemOpenSSHPrvKeyBytes)
	rsaParsed, ok := rawPrivateKey.(*rsa.PrivateKey)
	assert.True(ok)

	// Confirm RSA is valid
	assert.NoError(rsaParsed.Validate())
	// Confirm it matches the original key by comparing the public ones
	assert.True(rsaParsed.Equal(rsaOrig))
}

func TestOpenSSHFormat_MarshalAndUnmarshall_ECDSA(t *testing.T) {
	assert := testifyAssert.New(t)

	// Given an ECDSA private key
	ecdsaOrig, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	assert.NoError(err)

	// Marshall it to OpenSSH PEM format
	pemOpenSSHPrvKey, err := MarshalPrivateKey(ecdsaOrig, "")
	assert.NoError(err)
	pemOpenSSHPrvKeyBytes := pem.EncodeToMemory(pemOpenSSHPrvKey)

	// Parse it back into an ECDSA private key
	rawPrivateKey, err := ssh.ParseRawPrivateKey(pemOpenSSHPrvKeyBytes)
	ecdsaParsed, ok := rawPrivateKey.(*ecdsa.PrivateKey)
	assert.True(ok)

	// Confirm it matches the original key by comparing the public ones
	assert.True(ecdsaParsed.Equal(ecdsaOrig))
}

func TestOpenSSHFormat_MarshalAndUnmarshall_ED25519(t *testing.T) {
	assert := testifyAssert.New(t)

	// Given an ED25519 private key
	_, ed25519Orig, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(err)

	// Marshall it to OpenSSH PEM format
	pemOpenSSHPrvKey, err := MarshalPrivateKey(ed25519Orig, "")
	assert.NoError(err)
	pemOpenSSHPrvKeyBytes := pem.EncodeToMemory(pemOpenSSHPrvKey)

	// Parse it back into an ED25519 private key
	rawPrivateKey, err := ssh.ParseRawPrivateKey(pemOpenSSHPrvKeyBytes)
	ed25519Parsed, ok := rawPrivateKey.(*ed25519.PrivateKey)
	assert.True(ok)

	// Confirm it matches the original key by comparing the public ones
	assert.True(ed25519Parsed.Equal(ed25519Orig))
}
