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
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var keyUsages = map[string]x509.KeyUsage{
	"digital_signature":  x509.KeyUsageDigitalSignature,
	"content_commitment": x509.KeyUsageContentCommitment,
	"key_encipherment":   x509.KeyUsageKeyEncipherment,
	"data_encipherment":  x509.KeyUsageDataEncipherment,
	"key_agreement":      x509.KeyUsageKeyAgreement,
	"cert_signing":       x509.KeyUsageCertSign,
	"crl_signing":        x509.KeyUsageCRLSign,
	"encipher_only":      x509.KeyUsageEncipherOnly,
	"decipher_only":      x509.KeyUsageDecipherOnly,
}

var extendedKeyUsages = map[string]x509.ExtKeyUsage{
	"any_extended":                      x509.ExtKeyUsageAny,
	"server_auth":                       x509.ExtKeyUsageServerAuth,
	"client_auth":                       x509.ExtKeyUsageClientAuth,
	"code_signing":                      x509.ExtKeyUsageCodeSigning,
	"email_protection":                  x509.ExtKeyUsageEmailProtection,
	"ipsec_end_system":                  x509.ExtKeyUsageIPSECEndSystem,
	"ipsec_tunnel":                      x509.ExtKeyUsageIPSECTunnel,
	"ipsec_user":                        x509.ExtKeyUsageIPSECUser,
	"timestamping":                      x509.ExtKeyUsageTimeStamping,
	"ocsp_signing":                      x509.ExtKeyUsageOCSPSigning,
	"microsoft_server_gated_crypto":     x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"netscape_server_gated_crypto":      x509.ExtKeyUsageNetscapeServerGatedCrypto,
	"microsoft_commercial_code_signing": x509.ExtKeyUsageMicrosoftCommercialCodeSigning,
	"microsoft_kernel_code_signing":     x509.ExtKeyUsageMicrosoftKernelCodeSigning,
}

var signatureAlgorithms = map[string]x509.SignatureAlgorithm{
	"md2_rsa":       x509.MD2WithRSA,  // Unsupported
	"md5_rsa":       x509.MD5WithRSA,  // Only supported for signing, not verification.
	"sha1_rsa":      x509.SHA1WithRSA, // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	"sha256_rsa":    x509.SHA256WithRSA,
	"sha384_rsa":    x509.SHA384WithRSA,
	"sha512_rsa":    x509.SHA512WithRSA,
	"sha1_dsa":      x509.DSAWithSHA1,   // Unsupported.
	"sha256_dsa":    x509.DSAWithSHA256, // Unsupported.
	"sha1_ecdsa":    x509.ECDSAWithSHA1, // Only supported for signing, and verification of CRLs, CSRs, and OCSP responses.
	"sha256_ecdsa":  x509.ECDSAWithSHA256,
	"sha384_ecdsa":  x509.ECDSAWithSHA384,
	"sha512_ecdsa":  x509.ECDSAWithSHA512,
	"sha256_rsapss": x509.SHA256WithRSAPSS,
	"sha384_rsapss": x509.SHA384WithRSAPSS,
	"sha512_rsapss": x509.SHA512WithRSAPSS,
	"ed25519":       x509.PureEd25519,
}

func supportedHashingAlgorithms() []string {
	list := make([]string, 0, len(keyUsages)+len(signatureAlgorithms))

	for k := range signatureAlgorithms {
		if strings.Contains(k, "_") {
			alg := strings.Split(k, "_")[0]
			list = append(list, alg)
		}
	}
	allKeys := make(map[string]bool)
	res := []string{}
	for _, item := range list {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			res = append(res, item)
		}
	}
	sort.Strings(res)
	return res
}

// supportedKeyUsagesStr returns a slice with all the keys in keyUsages and extendedKeyUsages.
func supportedKeyUsagesStr() []string {
	res := make([]string, 0, len(keyUsages)+len(extendedKeyUsages))

	for k := range keyUsages {
		res = append(res, k)
	}
	for k := range extendedKeyUsages {
		res = append(res, k)
	}
	sort.Strings(res)

	return res
}

// generateSubjectKeyID generates a SHA-1 hash of the subject public key.
func generateSubjectKeyID(pubKey crypto.PublicKey) ([]byte, error) {
	var pubKeyBytes []byte
	var err error

	// Marshal public key to bytes or set an error
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		if pub != nil {
			pubKeyBytes, err = asn1.Marshal(*pub)
		} else {
			err = fmt.Errorf("received 'nil' pointer instead of public key")
		}
	case *ecdsa.PublicKey:
		//nolint:staticcheck // Reference: https://github.com/hashicorp/terraform-provider-tls/issues/480
		pubKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	case ed25519.PublicKey:
		pubKeyBytes, err = asn1.Marshal(pub)
	case *ed25519.PublicKey:
		if pub != nil {
			pubKeyBytes, err = asn1.Marshal(*pub)
		} else {
			err = fmt.Errorf("received 'nil' pointer instead of public key")
		}
	default:
		err = fmt.Errorf("unsupported public key type %T", pub)
	}

	// If any of the cases above failed, an error would have been set
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key of type %T: %w", pubKey, err)
	}

	pubKeyHash := sha1.Sum(pubKeyBytes)
	return pubKeyHash[:], nil
}

// getSignatureAlgorithm calculates the algorithm based on the public key and the desired hash.
func getSignatureAlgorithm(pubKey crypto.PublicKey, hashAlg string) (*x509.SignatureAlgorithm, error) {
	var err error
	var algorithm = strings.ToLower(hashAlg)

	// lookup algorithm from public key type
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		algorithm += "_rsa"
	case *ecdsa.PublicKey:
		algorithm += "_ecdsa"
	case ed25519.PublicKey:
		// no hash algorithm is required
		algorithm = "ed25519"
	case *ed25519.PublicKey:
		// no hash algorithm is required
		algorithm = "ed25519"
	default:
		err = fmt.Errorf("unsupported public key type %T", pub)
	}

	// If any of the cases above failed, an error would have been set
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key of type %T: %w", pubKey, err)
	}

	if sigAlgo, ok := signatureAlgorithms[algorithm]; ok {
		return &sigAlgo, nil
	}

	return nil, fmt.Errorf("unable to determine a signature algorithm from public key of type %T and %s hashing algorithm", pubKey, hashAlg)
}

func createCertificate(ctx context.Context, template, parent *x509.Certificate, pubKey crypto.PublicKey, prvKey crypto.PrivateKey, plan *tfsdk.Plan) (*commonCertificate, diag.Diagnostics) {
	var err error
	var diags diag.Diagnostics

	// Set not-before and not-after limits on the certificate template
	validityPeriodHoursPath := path.Root("validity_period_hours")
	var validityPeriodHours int64
	diags.Append(plan.GetAttribute(ctx, validityPeriodHoursPath, &validityPeriodHours)...)
	if diags.HasError() {
		return nil, diags
	}
	template.NotBefore = overridableTimeFunc()
	template.NotAfter = template.NotBefore.Add(time.Duration(validityPeriodHours) * time.Hour)

	// Set serial-number on the template
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	template.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		diags.AddError("Failed to generate serial number", err.Error())
		return nil, diags
	}

	// Set allowed-uses on the template
	allowedUsesPath := path.Root("allowed_uses")
	var allowedUses types.List
	diags.Append(plan.GetAttribute(ctx, allowedUsesPath, &allowedUses)...)
	if diags.HasError() {
		return nil, diags
	}
	if !allowedUses.IsNull() && !allowedUses.IsUnknown() && len(allowedUses.Elements()) > 0 {
		for _, keyUse := range allowedUses.Elements() {
			if usage, ok := keyUsages[keyUse.(types.String).ValueString()]; ok {
				template.KeyUsage |= usage
			}
			if usage, ok := extendedKeyUsages[keyUse.(types.String).ValueString()]; ok {
				template.ExtKeyUsage = append(template.ExtKeyUsage, usage)
			}
		}
	}

	// Set is-CA on the template
	isCACertificatePath := path.Root("is_ca_certificate")
	var isCACertificate types.Bool
	diags.Append(plan.GetAttribute(ctx, isCACertificatePath, &isCACertificate)...)
	if diags.HasError() {
		return nil, diags
	}
	if !isCACertificate.IsNull() && !isCACertificate.IsUnknown() && isCACertificate.ValueBool() {
		// NOTE: if the Certificate we are trying to create is a Certificate Authority,
		// then https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.6 requires
		// the `.Subject` to contain at least 1 Distinguished Name.
		if cmp.Equal(template.Subject, pkix.Name{}) {
			diags.AddError(
				"Invalid Certificate Subject",
				"Must contain at least one Distinguished Name when creating Certificate Authority (CA)",
			)
			return nil, diags
		}
		template.IsCA = true

		template.SubjectKeyId, err = generateSubjectKeyID(pubKey)
		if err != nil {
			diags.AddError("Failed to generate subject key identifier", err.Error())
			return nil, diags
		}
	}

	// Set signature-algorithm on the template
	hashAlgorithmPath := path.Root("hashing_algorithm")
	var hashAlgorithm types.String
	diags.Append(plan.GetAttribute(ctx, hashAlgorithmPath, &hashAlgorithm)...)
	if diags.HasError() {
		return nil, diags
	}
	if !hashAlgorithm.IsNull() && !hashAlgorithm.IsUnknown() {
		var sigAlg, err = getSignatureAlgorithm(pubKey, hashAlgorithm.ValueString())
		if err != nil {
			diags.AddError("Failed to generate signature algorithm", err.Error())
			return nil, diags
		}
		if sigAlg != nil {
			template.SignatureAlgorithm = *sigAlg
		}
	}

	// Set subject-id on the template
	setSubjectKeyIDPath := path.Root("set_subject_key_id")
	var setSubjectKeyID types.Bool
	diags.Append(plan.GetAttribute(ctx, setSubjectKeyIDPath, &setSubjectKeyID)...)
	if diags.HasError() {
		return nil, diags
	}
	if !setSubjectKeyID.IsNull() && !setSubjectKeyID.IsUnknown() && setSubjectKeyID.ValueBool() {
		template.SubjectKeyId, err = generateSubjectKeyID(pubKey)
		if err != nil {
			diags.AddError("Failed to generate subject key identifier", err.Error())
			return nil, diags
		}
	}

	// Set authority-id on the template
	_, ok := plan.Schema.GetAttributes()["set_authority_key_id"]
	if ok {
		setAuthorityKeyIDPath := path.Root("set_authority_key_id")
		var setAuthorityKeyID types.Bool
		diags.Append(plan.GetAttribute(ctx, setAuthorityKeyIDPath, &setAuthorityKeyID)...)
		if diags.HasError() {
			return nil, diags
		}
		if !setAuthorityKeyID.IsNull() && !setAuthorityKeyID.IsUnknown() && setAuthorityKeyID.ValueBool() {
			if len(parent.SubjectKeyId) == 0 {
				diags.AddError(
					"Invalid Certificate Authority",
					"Could not determine Authority Key Identifier",
				)
				return nil, diags
			}

			template.AuthorityKeyId = parent.SubjectKeyId
		}
	}

	// Creating the certificate and encoding it to PEM
	tflog.Debug(ctx, "Creating certificate", map[string]interface{}{
		"template": fmt.Sprintf("%+v", template),
		"parent":   fmt.Sprintf("%+v", parent),
	})
	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pubKey, prvKey)
	if err != nil {
		diags.AddError("Failed to create certificate", err.Error())
		return nil, diags
	}
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: PreambleCertificate.String(), Bytes: certBytes}))

	validFromBytes, err := template.NotBefore.MarshalText()
	if err != nil {
		diags.AddError("Failed to serialize validity start time", err.Error())
		return nil, diags
	}
	validToBytes, err := template.NotAfter.MarshalText()
	if err != nil {
		diags.AddError("Failed to serialize validity end time", err.Error())
		return nil, diags
	}

	// Finally, storing the key computed values in the state
	return &commonCertificate{
		id:                template.SerialNumber.String(),
		certPem:           certPem,
		validityStartTime: string(validFromBytes),
		validityEndTime:   string(validToBytes),
	}, nil
}

type commonCertificate struct {
	id                string
	certPem           string
	validityStartTime string
	validityEndTime   string
}

func modifyPlanIfCertificateReadyForRenewal(ctx context.Context, req *resource.ModifyPlanRequest, res *resource.ModifyPlanResponse) {
	// Retrieve `validity_end_time` and confirm is a known, non-null value
	validityEndTimePath := path.Root("validity_end_time")
	var validityEndTimeStr types.String
	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, validityEndTimePath, &validityEndTimeStr)...)
	if res.Diagnostics.HasError() {
		return
	}
	if validityEndTimeStr.IsNull() || validityEndTimeStr.IsUnknown() {
		return
	}

	// Parse `validity_end_time`
	validityEndTime, err := time.Parse(time.RFC3339, validityEndTimeStr.ValueString())
	if err != nil {
		res.Diagnostics.AddError(
			fmt.Sprintf("Failed to parse data from string: %s", validityEndTimeStr.ValueString()),
			err.Error(),
		)
		return
	}

	// Retrieve `early_renewal_hours`
	earlyRenewalHoursPath := path.Root("early_renewal_hours")
	var earlyRenewalHours int64
	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, earlyRenewalHoursPath, &earlyRenewalHours)...)
	if res.Diagnostics.HasError() {
		return
	}

	currentTime := overridableTimeFunc()

	// Determine the time from which an "early renewal" is possible
	earlyRenewalPeriod := time.Duration(-earlyRenewalHours) * time.Hour
	earlyRenewalTime := validityEndTime.Add(earlyRenewalPeriod)

	// If "early renewal" time has passed, mark it "ready for renewal"
	timeToEarlyRenewal := earlyRenewalTime.Sub(currentTime)
	if timeToEarlyRenewal <= 0 {
		tflog.Info(ctx, "Certificate is ready for early renewal")
		readyForRenewalPath := path.Root("ready_for_renewal")
		res.Diagnostics.Append(res.Plan.SetAttribute(ctx, readyForRenewalPath, types.BoolUnknown())...)
		res.RequiresReplace = append(res.RequiresReplace, readyForRenewalPath)
	}
}

func modifyStateIfCertificateReadyForRenewal(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// Retrieve `validity_end_time` and confirm is a known, non-null value
	validityEndTimePath := path.Root("validity_end_time")
	var validityEndTimeStr types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, validityEndTimePath, &validityEndTimeStr)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if validityEndTimeStr.IsNull() || validityEndTimeStr.IsUnknown() {
		return
	}

	// Parse `validity_end_time`
	validityEndTime, err := time.Parse(time.RFC3339, validityEndTimeStr.ValueString())
	if err != nil {
		resp.Diagnostics.AddError(
			fmt.Sprintf("Failed to parse data from string: %s", validityEndTimeStr.ValueString()),
			err.Error(),
		)
		return
	}

	// Retrieve `early_renewal_hours`
	earlyRenewalHoursPath := path.Root("early_renewal_hours")
	var earlyRenewalHours int64
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, earlyRenewalHoursPath, &earlyRenewalHours)...)
	if resp.Diagnostics.HasError() {
		return
	}

	currentTime := overridableTimeFunc()

	// Determine the time from which an "early renewal" is possible
	earlyRenewalPeriod := time.Duration(-earlyRenewalHours) * time.Hour
	earlyRenewalTime := validityEndTime.Add(earlyRenewalPeriod)

	// If "early renewal" time has passed, mark it "ready for renewal"
	timeToEarlyRenewal := earlyRenewalTime.Sub(currentTime)
	if timeToEarlyRenewal <= 0 {
		tflog.Info(ctx, "Certificate is ready for early renewal")
		readyForRenewalPath := path.Root("ready_for_renewal")
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, readyForRenewalPath, true)...)
	}
}

// createSubjectDistinguishedNames return a *pkix.Name (i.e. a "Certificate Subject") if the non-empty.
// This used for creating x509.Certificate or x509.CertificateRequest.
func createSubjectDistinguishedNames(ctx context.Context, subject certificateSubjectModel) pkix.Name {
	result := pkix.Name{}

	if !subject.CommonName.IsNull() && !subject.CommonName.IsUnknown() {
		result.CommonName = subject.CommonName.ValueString()
	}

	if !subject.Organization.IsNull() && !subject.Organization.IsUnknown() {
		result.Organization = []string{subject.Organization.ValueString()}
	}

	if !subject.OrganizationalUnit.IsNull() && !subject.OrganizationalUnit.IsUnknown() {
		result.OrganizationalUnit = []string{subject.OrganizationalUnit.ValueString()}
	}

	if !subject.StreetAddress.IsNull() && !subject.StreetAddress.IsUnknown() {
		subject.StreetAddress.ElementsAs(ctx, &result.StreetAddress, false)
	}

	if !subject.Locality.IsNull() && !subject.Locality.IsUnknown() {
		result.Locality = []string{subject.Locality.ValueString()}
	}

	if !subject.Province.IsNull() && !subject.Province.IsUnknown() {
		result.Province = []string{subject.Province.ValueString()}
	}

	if !subject.Country.IsNull() && !subject.Country.IsUnknown() {
		result.Country = []string{subject.Country.ValueString()}
	}

	if !subject.PostalCode.IsNull() && !subject.PostalCode.IsUnknown() {
		result.PostalCode = []string{subject.PostalCode.ValueString()}
	}

	if !subject.SerialNumber.IsNull() && !subject.SerialNumber.IsUnknown() {
		result.SerialNumber = subject.SerialNumber.ValueString()
	}

	return result
}
