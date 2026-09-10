// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"testing"
)

func TestGenerateSubjectKeyID_ECDSA(t *testing.T) {
	testCases := []struct {
		name  string
		curve elliptic.Curve
	}{
		{name: "P224", curve: elliptic.P224()},
		{name: "P256", curve: elliptic.P256()},
		{name: "P384", curve: elliptic.P384()},
		{name: "P521", curve: elliptic.P521()},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}

			actual, err := generateSubjectKeyID(&key.PublicKey)
			if err != nil {
				t.Fatal(err)
			}

			expected := sha1.Sum(uncompressedECDSAPublicKeyBytes(t, &key.PublicKey))
			if !bytes.Equal(actual, expected[:]) {
				t.Fatalf("unexpected subject key ID\nexpected: %x\nactual:   %x", expected, actual)
			}
		})
	}
}

func TestGenerateSubjectKeyID_nilECDSAPublicKey(t *testing.T) {
	_, err := generateSubjectKeyID((*ecdsa.PublicKey)(nil))
	if err == nil {
		t.Fatal("expected error")
	}
}

func uncompressedECDSAPublicKeyBytes(t *testing.T, pub *ecdsa.PublicKey) []byte {
	t.Helper()

	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	result := make([]byte, 1+2*byteLen)
	result[0] = 4
	pub.X.FillBytes(result[1 : 1+byteLen])
	pub.Y.FillBytes(result[1+byteLen:])

	return result
}
