package tls

import (
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/hex"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"tls_private_key":         resourcePrivateKey(),
			"tls_locally_signed_cert": resourceLocallySignedCert(),
			"tls_self_signed_cert":    resourceSelfSignedCert(),
			"tls_cert_request":        resourceCertRequest(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"tls_public_key": dataSourcePublicKey(),
		},
	}
}

func hashForState(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}

// Create a PKIX Name from the subject resource
func nameFromResourceData(nameMap map[string]interface{}) (*pkix.Name, error) {
	result := &pkix.Name{}

	if value := nameMap["common_name"]; value != "" {
		result.CommonName = value.(string)
	}

	result.Organization = convertResourceToStrings("organization", nameMap)
	result.OrganizationalUnit = convertResourceToStrings("organizational_unit", nameMap)
	result.StreetAddress = convertResourceToStrings("street_address", nameMap)
	result.Locality = convertResourceToStrings("locality", nameMap)
	result.Province = convertResourceToStrings("province", nameMap)
	result.Country = convertResourceToStrings("country", nameMap)
	result.PostalCode = convertResourceToStrings("postal_code", nameMap)

	if value := nameMap["serial_number"]; value != "" {
		result.SerialNumber = value.(string)
	}

	return result, nil
}

// Convert a Resource that is a list of strings to a []string
func convertResourceToStrings(key string, in map[string]interface{}) []string {
	// start with a map of string to interface{} and look up the interface{} for the given string
	// then convert the interface() to a slice of interface{}
	// then convert the slice of interface{} to a slice of string, or nil if no elements
	// panic at any step if something isn't right
	v := in[key].([]interface{})
	if len(v) == 0 {
		return nil
	}
	out := make([]string, len(v))
	for i, vi := range v {
		out[i] = vi.(string)
	}
	return out
}

var nameSchema *schema.Resource = &schema.Resource{
	Schema: map[string]*schema.Schema{
		"organization": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ForceNew:      true,
			PromoteSingle: true,
		},
		"common_name": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
		"organizational_unit": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ForceNew:      true,
			PromoteSingle: true,
		},
		"street_address": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional: true,
			ForceNew: true,
		},
		"locality": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ForceNew:      true,
			PromoteSingle: true,
		},
		"province": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ForceNew:      true,
			PromoteSingle: true,
		},
		"country": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ForceNew:      true,
			PromoteSingle: true,
		},
		"postal_code": &schema.Schema{
			Type: schema.TypeList,
			Elem: &schema.Schema{
				Type: schema.TypeString,
			},
			Optional:      true,
			ForceNew:      true,
			PromoteSingle: true,
		},
		"serial_number": &schema.Schema{
			Type:     schema.TypeString,
			Optional: true,
			ForceNew: true,
		},
	},
}
