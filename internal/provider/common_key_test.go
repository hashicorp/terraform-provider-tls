// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"crypto/mldsa"
	"testing"
)

// TestMLDSAAlgorithms confirms that the ML-DSA algorithms are the three FIPS 204
// parameter sets, named as the standard library names them, and that each round-trips
// between its name and the parameter set it stands for.
func TestMLDSAAlgorithms(t *testing.T) {
	expected := map[Algorithm]mldsa.Parameters{
		MLDSA44: mldsa.MLDSA44(),
		MLDSA65: mldsa.MLDSA65(),
		MLDSA87: mldsa.MLDSA87(),
	}

	algorithms := mldsaAlgorithms()
	if len(algorithms) != len(expected) {
		t.Fatalf("expected %d ML-DSA algorithms, got %d", len(expected), len(algorithms))
	}

	for algorithm, want := range expected {
		if got := algorithms[algorithm]; got != want {
			t.Errorf("%s stands for %s", algorithm, got)
		}
		if got := want.String(); got != algorithm.String() {
			t.Errorf("algorithm is named %q, standard library calls it %q", algorithm, got)
		}
		got, err := mldsaAlgorithm(want)
		if err != nil {
			t.Errorf("%s: %s", algorithm, err)
			continue
		}
		if got != algorithm {
			t.Errorf("%s maps back onto %s", want, got)
		}
	}
}

// TestMLDSAAlgorithmsAreSupported guards against an ML-DSA algorithm being reachable
// through the schema without a generator behind it, or the other way round.
func TestMLDSAAlgorithmsAreSupported(t *testing.T) {
	supported := make(map[Algorithm]bool, len(supportedAlgorithms()))
	for _, algorithm := range supportedAlgorithms() {
		supported[algorithm] = true
	}

	for algorithm := range mldsaAlgorithms() {
		if !supported[algorithm] {
			t.Errorf("%s is not offered by supportedAlgorithms", algorithm)
		}
		if _, ok := keyGenerators[algorithm]; !ok {
			t.Errorf("%s has no key generator", algorithm)
		}
	}
}

func TestMLDSAAlgorithmRejectsUnknownParameterSet(t *testing.T) {
	if _, err := mldsaAlgorithm(mldsa.Parameters{}); err == nil {
		t.Fatal("expected an error for an unsupported parameter set, got none")
	}
}
