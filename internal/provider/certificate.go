package provider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"math/big"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
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

func supportedKeyUsages() []string {
	res := make([]string, 0, len(keyUsages)+len(extendedKeyUsages))
	for k, _ := range keyUsages {
		res = append(res, k)
	}
	for k, _ := range extendedKeyUsages {
		res = append(res, k)
	}
	return res
}

// generateSubjectKeyID generates a SHA-1 hash of the subject public key.
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var publicKeyBytes []byte
	var err error

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(*pub)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		publicKeyBytes = elliptic.Marshal(pub.Curve, pub.X, pub.Y)
	default:
		return nil, errors.New("only RSA and ECDSA public keys supported")
	}

	hash := sha1.Sum(publicKeyBytes)
	return hash[:], nil
}

// setCertificateSubjectSchema sets on the given reference to map of schema.Schema
// all the keys required by a resource representing a certificate's subject.
func setCertificateSubjectSchema(s *map[string]*schema.Schema) {
	(*s)["dns_names"] = &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "List of DNS names for which a certificate is being requested (i.e. certificate subjects).",
	}

	(*s)["ip_addresses"] = &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "List of IP addresses for which a certificate is being requested (i.e. certificate subjects).",
	}

	(*s)["uris"] = &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
		},
		Description: "List of URIs for which a certificate is being requested (i.e. certificate subjects).",
	}

	(*s)["key_algorithm"] = &schema.Schema{
		Type:        schema.TypeString,
		Required:    true,
		ForceNew:    true,
		Description: "Name of the algorithm used when generating the private key provided in `private_key_pem`.",
	}

	(*s)["private_key_pem"] = &schema.Schema{
		Type:      schema.TypeString,
		Required:  true,
		ForceNew:  true,
		Sensitive: true,
		StateFunc: func(v interface{}) string {
			return hashForState(v.(string))
		},
		Description: "PEM-encoded private key that the certificate will belong to. " +
			"This can be read from a separate file using the `file` interpolation function. " +
			"Only an irreversible secure hash of the private key will be stored in the Terraform state.",
	}

	(*s)["subject"] = &schema.Schema{
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
func setCertificateCommonSchema(s *map[string]*schema.Schema) {
	(*s)["validity_period_hours"] = &schema.Schema{
		Type:             schema.TypeInt,
		Required:         true,
		ForceNew:         true,
		ValidateDiagFunc: validation.ToDiagFunc(validation.IntAtLeast(0)),
		Description:      "Number of hours, after initial issuing, that the certificate will remain valid for.",
	}

	(*s)["early_renewal_hours"] = &schema.Schema{
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

	(*s)["is_ca_certificate"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		ForceNew:    true,
		Description: "Is the generated certificate representing a Certificate Authority (CA) (default: `false`).",
	}

	(*s)["allowed_uses"] = &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		ForceNew: true,
		Elem: &schema.Schema{
			Type:         schema.TypeString,
			ValidateFunc: validation.StringInSlice(supportedKeyUsages(), false),
		},
		Description: "List of key usages allowed for the issued certificate. " +
			"Values are defined in [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280) " +
			"and combine flags defined by both " +
			"[Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3) " +
			"and [Extended Key Usages](https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.12). " +
			fmt.Sprintf("Accepted values: `%s`.", strings.Join(supportedKeyUsages(), "`, `")),
	}

	(*s)["cert_pem"] = &schema.Schema{
		Type:        schema.TypeString,
		Computed:    true,
		Description: "Certificate data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
	}

	(*s)["ready_for_renewal"] = &schema.Schema{
		Type:     schema.TypeBool,
		Computed: true,
		Description: "Is the certificate either expired (i.e. beyond the `validity_period_hours`) " +
			"or ready for an early renewal (i.e. within the `early_renewal_hours`)?",
	}

	(*s)["validity_start_time"] = &schema.Schema{
		Type:     schema.TypeString,
		Computed: true,
		Description: "The time after which the certificate is valid, " +
			"expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
	}

	(*s)["validity_end_time"] = &schema.Schema{
		Type:     schema.TypeString,
		Computed: true,
		Description: "The time until which the certificate is invalid, " +
			"expressed as an [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
	}

	(*s)["set_subject_key_id"] = &schema.Schema{
		Type:        schema.TypeBool,
		Optional:    true,
		ForceNew:    true,
		Description: "Should the generated certificate include a subject key identifier (default: `false`).",
	}

	(*s)["id"] = &schema.Schema{
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
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: Certificate.String(), Bytes: certBytes}))

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
