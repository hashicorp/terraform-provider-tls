package provider

import (
	"context"
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/hex"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"os"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type TlsProvConfig struct {
	useProxy bool
}

func New() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"tls_private_key":         resourcePrivateKey(),
			"tls_locally_signed_cert": resourceLocallySignedCert(),
			"tls_self_signed_cert":    resourceSelfSignedCert(),
			"tls_cert_request":        resourceCertRequest(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"tls_public_key":  dataSourcePublicKey(),
			"tls_certificate": dataSourceTlsCertificate(),
		},
		ConfigureContextFunc: providerConfigure,
	}
}

func hashForState(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}

func providerConfigure(ctx context.Context, d *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics

	_, ok := os.LookupEnv("TF_TLS_USE_ENV_PROXY")
	cfg := TlsProvConfig{useProxy: false}
	if ok {
		cfg.useProxy = true
	}
	return &cfg, diags
}

func nameFromResourceData(nameMap map[string]interface{}) (*pkix.Name, error) {
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

	return result, nil
}

var nameSchema *schema.Resource = &schema.Resource{
	Schema: map[string]*schema.Schema{
		"organization": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"common_name": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"organizational_unit": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"street_address": {
			Type:     schema.TypeList,
			Optional: true,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			ForceNew: true,
		},
		"locality": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"province": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"country": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"postal_code": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"serial_number": {
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
	},
}
