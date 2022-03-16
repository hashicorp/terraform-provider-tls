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
	"math/big"
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

var extKeyUsages = map[string]x509.ExtKeyUsage{
	"any_extended":                  x509.ExtKeyUsageAny,
	"server_auth":                   x509.ExtKeyUsageServerAuth,
	"client_auth":                   x509.ExtKeyUsageClientAuth,
	"code_signing":                  x509.ExtKeyUsageCodeSigning,
	"email_protection":              x509.ExtKeyUsageEmailProtection,
	"ipsec_end_system":              x509.ExtKeyUsageIPSECEndSystem,
	"ipsec_tunnel":                  x509.ExtKeyUsageIPSECTunnel,
	"ipsec_user":                    x509.ExtKeyUsageIPSECUser,
	"timestamping":                  x509.ExtKeyUsageTimeStamping,
	"ocsp_signing":                  x509.ExtKeyUsageOCSPSigning,
	"microsoft_server_gated_crypto": x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	"netscape_server_gated_crypto":  x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// rsaPublicKey reflects the ASN.1 structure of a PKCS#1 public key.
type rsaPublicKey struct {
	N *big.Int
	E int
}

var now = func() time.Time {
	return time.Now()
}

// generateSubjectKeyID generates a SHA-1 hash of the subject public key.
func generateSubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	var publicKeyBytes []byte
	var err error

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		publicKeyBytes, err = asn1.Marshal(rsaPublicKey{N: pub.N, E: pub.E})
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

func resourceCertificateCommonSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"validity_period_hours": {
			Type:        schema.TypeInt,
			Required:    true,
			Description: "Number of hours that the certificate will remain valid for",
			ForceNew:    true,
		},

		"early_renewal_hours": {
			Type:        schema.TypeInt,
			Optional:    true,
			Default:     0,
			Description: "Number of hours before the certificates expiry when a new certificate will be generated",
		},

		"is_ca_certificate": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "Whether the generated certificate will be usable as a CA certificate",
			ForceNew:    true,
		},

		"allowed_uses": {
			Type:        schema.TypeList,
			Required:    true,
			Description: "Uses that are allowed for the certificate",
			ForceNew:    true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
		},

		"cert_pem": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"ready_for_renewal": {
			Type:     schema.TypeBool,
			Computed: true,
		},

		"validity_start_time": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"validity_end_time": {
			Type:     schema.TypeString,
			Computed: true,
		},

		"set_subject_key_id": {
			Type:        schema.TypeBool,
			Optional:    true,
			Description: "If true, the generated certificate will include a subject key identifier.",
			ForceNew:    true,
		},
	}
}

func createCertificate(d *schema.ResourceData, template, parent *x509.Certificate, pub crypto.PublicKey, priv interface{}) error {
	var err error

	template.NotBefore = now()
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
		if usage, ok := extKeyUsages[keyUse]; ok {
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
	endTime := now()
	err := endTime.UnmarshalText([]byte(endTimeStr))
	if err != nil {
		// If end time is invalid then we'll treat it as being at the time for renewal.
		readyForRenewal = true
	} else {
		earlyRenewalHours := d.Get("early_renewal_hours").(int)
		earlyRenewalPeriod := time.Duration(-earlyRenewalHours) * time.Hour
		endTime = endTime.Add(earlyRenewalPeriod)

		currentTime := now()
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

var subjectAttributesResource = &schema.Resource{
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
}
