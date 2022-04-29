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

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
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

// supportedKeyUsages returns a slice with all the keys in keyUsages and extendedKeyUsages.
func supportedKeyUsages() []string {
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

// setCertificateSubjectSchema sets on the given reference to map of schema.Schema
// all the keys required by a resource representing a certificate's subject.
func setCertificateSubjectSchema(s map[string]*schema.Schema) {
	s["dns_names"] = &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "List of DNS names for which a certificate is being requested (i.e. certificate subjects).",
	}

	s["ip_addresses"] = &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "List of IP addresses for which a certificate is being requested (i.e. certificate subjects).",
	}

	s["uris"] = &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "List of URIs for which a certificate is being requested (i.e. certificate subjects).",
	}

	s["key_algorithm"] = &schema.Schema{
		Type:       schema.TypeString,
		Optional:   true,
		Computed:   true,
		ForceNew:   true,
		Deprecated: "This is now ignored, as the key algorithm is inferred from the `private_key_pem`.",
		Description: "Name of the algorithm used when generating the private key provided in `private_key_pem`. " +
			"**NOTE**: this is deprecated and ignored, as the key algorithm is now inferred from the key. ",
	}

	s["private_key_pem"] = &schema.Schema{
		Type:      schema.TypeString,
		Required:  true,
		ForceNew:  true,
		Sensitive: true,
		StateFunc: func(v interface{}) string {
			return hashForState(v.(string))
		},
		Description: "Private key in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format, " +
			"that the certificate will belong to. " +
			"This can be read from a separate file using the [`file`](https://www.terraform.io/language/functions/file) " +
			"interpolation function. " +
			"Only an irreversible secure hash of the private key will be stored in the Terraform state.",
	}

	s["subject"] = &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		ForceNew: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"organization": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `O`",
				},
				"common_name": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `CN`",
				},
				"organizational_unit": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `OU`",
				},
				"street_address": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
					ForceNew:    true,
					Description: "Distinguished name: `STREET`",
				},
				"locality": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `L`",
				},
				"province": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `ST`",
				},
				"country": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `C`",
				},
				"postal_code": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `PC`",
				},
				"serial_number": {
					Type:        schema.TypeString,
					Optional:    true,
					ForceNew:    true,
					Description: "Distinguished name: `SERIALNUMBER`",
				},
			},
		},
		Description: "The subject for which a certificate is being requested. " +
			"The acceptable arguments are all optional and their naming is based upon " +
			"[Issuer Distinguished Names (RFC5280)](https://tools.ietf.org/html/rfc5280#section-4.1.2.4) section.",
	}
}

// setCertificateCommonSchema sets on the given reference to map of schema.Schema
// all the keys required by a resource representing a certificate.
func setCertificateCommonSchema(s map[string]*schema.Schema) {
	s["validity_period_hours"] = &schema.Schema{
		Type:             schema.TypeInt,
		Required:         true,
		ForceNew:         true,
		ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(0)),
		Description:      "Number of hours, after initial issuing, that the certificate will remain valid for.",
	}

	s["early_renewal_hours"] = &schema.Schema{
		Type:             schema.TypeInt,
		Optional:         true,
		Default:          0,
		ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(0)),
		Description: "The resource will consider the certificate to have expired the given number of hours " +
			"before its actual expiry time. This can be useful to deploy an updated certificate in advance of " +
			"the expiration of the current certificate. " +
			"However, the old certificate remains valid until its true expiration time, since this resource " +
			"does not (and cannot) support certificate revocation. " +
			"Also, this advance update can only be performed should the Terraform configuration be applied " +
			"during the early renewal period. (default: `0`)",
	}

	s["is_ca_certificate"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		ForceNew:    true,
		Description: "Is the generated certificate representing a Certificate Authority (CA) (default: `false`).",
	}

	s["allowed_uses"] = &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type:             schema.TypeString,
			ValidateDiagFunc: StringInSliceOrWarn(supportedKeyUsages(), false),
		},
		Description: "List of key usages allowed for the issued certificate. " +
			"Values are defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) " +
			"and combine flags defined by both " +
			"[Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) " +
			"and [Extended Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12). " +
			fmt.Sprintf("Accepted values: `%s`.", strings.Join(supportedKeyUsages(), "`, `")),
	}

	s["cert_pem"] = &schema.Schema{
		Type:     schema.TypeString,
		Computed: true,
		Description: "Certificate data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
			"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
			"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
			"value append a `\\n` at the end of the PEM. " +
			"In case this disrupts your use case, we recommend using " +
			"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
	}

	s["ready_for_renewal"] = &schema.Schema{
		Type:     schema.TypeBool,
		Computed: true,
		Description: "Is the certificate either expired (i.e. beyond the `validity_period_hours`) " +
			"or ready for an early renewal (i.e. within the `early_renewal_hours`)?",
	}

	s["validity_start_time"] = &schema.Schema{
		Type:     schema.TypeString,
		Computed: true,
		Description: "The time after which the certificate is valid, " +
			"expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
	}

	s["validity_end_time"] = &schema.Schema{
		Type:     schema.TypeString,
		Computed: true,
		Description: "The time until which the certificate is invalid, " +
			"expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
	}

	s["set_subject_key_id"] = &schema.Schema{
		Type:     schema.TypeBool,
		Optional: true,
		ForceNew: true,
		Description: "Should the generated certificate include a " +
			"[subject key identifier](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.2) (default: `false`).",
	}

	s["id"] = &schema.Schema{
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Unique identifier for this resource: the certificate serial number.",
	}
}

func createCertificate(d *schema.ResourceData, template, parent *x509.Certificate, pub crypto.PublicKey, priv interface{}) error {
	var err error

	template.NotBefore = overridableTimeFunc()
	validityPeriodHours := d.Get("validity_period_hours").(int)
	template.NotAfter = template.NotBefore.Add(time.Duration(validityPeriodHours) * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	template.SerialNumber, err = rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}

	keyUsesI := d.Get("allowed_uses").([]interface{})
	for _, keyUseI := range keyUsesI {
		keyUse := keyUseI.(string)
		if usage, ok := keyUsages[keyUse]; ok {
			template.KeyUsage |= usage
		}
		if usage, ok := extendedKeyUsages[keyUse]; ok {
			template.ExtKeyUsage = append(template.ExtKeyUsage, usage)
		}
	}

	if d.Get("is_ca_certificate").(bool) {
		template.IsCA = true

		template.SubjectKeyId, err = generateSubjectKeyID(pub)
		if err != nil {
			return fmt.Errorf("failed to set subject key identifier: %s", err)
		}
	}

	if d.Get("set_subject_key_id").(bool) {
		template.SubjectKeyId, err = generateSubjectKeyID(pub)
		if err != nil {
			return fmt.Errorf("failed to set subject key identifier: %s", err)
		}
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return fmt.Errorf("error creating certificate: %s", err)
	}
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: PreambleCertificate.String(), Bytes: certBytes}))

	validFromBytes, err := template.NotBefore.MarshalText()
	if err != nil {
		return fmt.Errorf("error serializing validity_start_time: %s", err)
	}
	validToBytes, err := template.NotAfter.MarshalText()
	if err != nil {
		return fmt.Errorf("error serializing validity_end_time: %s", err)
	}

	d.SetId(template.SerialNumber.String())
	if err := d.Set("cert_pem", certPem); err != nil {
		return fmt.Errorf("error setting value on key 'cert_pem': %s", err)
	}
	if err := d.Set("ready_for_renewal", false); err != nil {
		return fmt.Errorf("error setting value on key 'ready_for_renewal': %s", err)
	}
	if err := d.Set("validity_start_time", string(validFromBytes)); err != nil {
		return fmt.Errorf("error setting value on key 'validity_start_time': %s", err)
	}
	if err := d.Set("validity_end_time", string(validToBytes)); err != nil {
		return fmt.Errorf("error setting value on key 'validity_end_time': %s", err)
	}

	return nil
}

func deleteCertificate(d *schema.ResourceData, _ interface{}) error {
	d.SetId("")
	return nil
}

func readCertificate(_ *schema.ResourceData, _ interface{}) error {
	return nil
}

func customizeCertificateDiff(_ context.Context, d *schema.ResourceDiff, _ interface{}) error {
	var readyForRenewal bool

	endTimeStr := d.Get("validity_end_time").(string)
	endTime := overridableTimeFunc()
	err := endTime.UnmarshalText([]byte(endTimeStr))
	if err != nil {
		// If end time is invalid then we'll treat it as being at the time for renewal.
		readyForRenewal = true
	} else {
		earlyRenewalHours := d.Get("early_renewal_hours").(int)
		earlyRenewalPeriod := time.Duration(-earlyRenewalHours) * time.Hour
		endTime = endTime.Add(earlyRenewalPeriod)

		currentTime := overridableTimeFunc()
		timeToRenewal := endTime.Sub(currentTime)
		if timeToRenewal <= 0 {
			readyForRenewal = true
		}
	}

	if readyForRenewal {
		err = d.SetNew("ready_for_renewal", true)
		if err != nil {
			return err
		}
		err = d.ForceNew("ready_for_renewal")
		if err != nil {
			return err
		}
	}

	return nil
}

func updateCertificate(_ *schema.ResourceData, _ interface{}) error {
	return nil
}

// distinguishedNamesFromSubjectAttributes it takes a map subject attributes and
// converts it to a pkix.Name (X.509 distinguished names).
func distinguishedNamesFromSubjectAttributes(nameMap map[string]interface{}) *pkix.Name {
	result := &pkix.Name{}

	if value := nameMap["common_name"]; value != "" {
		result.CommonName = value.(string)
	}
	if value := nameMap["organization"]; value != "" {
		result.Organization = []string{value.(string)}
	}
	if value := nameMap["organizational_unit"]; value != "" {
		result.OrganizationalUnit = []string{value.(string)}
	}
	if value := nameMap["street_address"].([]interface{}); len(value) > 0 {
		result.StreetAddress = make([]string, len(value))
		for i, vi := range value {
			result.StreetAddress[i] = vi.(string)
		}
	}
	if value := nameMap["locality"]; value != "" {
		result.Locality = []string{value.(string)}
	}
	if value := nameMap["province"]; value != "" {
		result.Province = []string{value.(string)}
	}
	if value := nameMap["country"]; value != "" {
		result.Country = []string{value.(string)}
	}
	if value := nameMap["postal_code"]; value != "" {
		result.PostalCode = []string{value.(string)}
	}
	if value := nameMap["serial_number"]; value != "" {
		result.SerialNumber = value.(string)
	}

	return result
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
	block, err := decodePEM(d, pemKey, PreambleCertificateRequest.String())
	if err != nil {
		return nil, err
	}

	certReq, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %s: %s", pemKey, err)
	}

	return certReq, nil
}

func certificateToMap(cert *x509.Certificate) map[string]interface{} {
	return map[string]interface{}{
		"signature_algorithm":  cert.SignatureAlgorithm.String(),
		"public_key_algorithm": cert.PublicKeyAlgorithm.String(),
		"serial_number":        cert.SerialNumber.String(),
		"is_ca":                cert.IsCA,
		"version":              cert.Version,
		"issuer":               cert.Issuer.String(),
		"subject":              cert.Subject.String(),
		"not_before":           cert.NotBefore.Format(time.RFC3339),
		"not_after":            cert.NotAfter.Format(time.RFC3339),
		"sha1_fingerprint":     fmt.Sprintf("%x", sha1.Sum(cert.Raw)),
	}
}

// StringInSliceOrWarn returns a SchemaValidateFunc which tests if the provided value
// is of type string and matches the value of an element in the valid slice.
//
// Differently from validation.StringInSlice, if the element is not part of the valid slice,
// a warning is produced.
func StringInSliceOrWarn(valid []string, ignoreCase bool) schema.SchemaValidateDiagFunc {
	return validation.ToDiagFunc(func(i interface{}, k string) (warnings []string, errors []error) {
		v, ok := i.(string)
		if !ok {
			errors = append(errors, fmt.Errorf("expected type of %s to be string", k))
			return warnings, errors
		}

		for _, str := range valid {
			if v == str || (ignoreCase && strings.EqualFold(v, str)) {
				return warnings, errors
			}
		}

		warnings = append(warnings, fmt.Sprintf("expected %s to be one of %v, got %s so will ignored", k, valid, v))
		return warnings, errors
	})
}
