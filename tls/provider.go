package tls

import (
	"crypto/sha1"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
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

func extensionFromResourceData(extensionMap map[string]interface{}) (*pkix.Extension, error) {
	result := &pkix.Extension{}

	// Handle the oid
	oidParts := strings.Split(extensionMap["oid"].(string), ".")
	oid := make(asn1.ObjectIdentifier, len(oidParts), len(oidParts))
	for i, part := range oidParts {
		intPart, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("Invalid Extension OID %#v", extensionMap["oid"].(string))
		}
		oid[i] = intPart
	}
	result.Id = oid

	// Handle the critical flag
	result.Critical = extensionMap["critical"].(bool)

	// Handle the value
	valueField := extensionMap["type"].(string) + "_value"
	switch valueField {
	case "integer_value":
		value := extensionMap["integer_value"].(int)
		marshalledValue, err := asn1.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal value %#v", value)
		}
		result.Value = marshalledValue
	case "boolean_value":
		value := extensionMap["boolean_value"].(bool)
		marshalledValue, err := asn1.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal value %#v", value)
		}
		result.Value = marshalledValue
	case "printable_string_value":
		value := extensionMap["printable_string_value"].(string)
		marshalledValue, err := asn1.MarshalWithParams(value, "printable")
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal value %#v", value)
		}
		result.Value = marshalledValue
	case "utf8_string_value":
		value := extensionMap["utf8_string_value"].(string)
		marshalledValue, err := asn1.MarshalWithParams(value, "utf8")
		if err != nil {
			return nil, fmt.Errorf("Failed to marshal value %#v", value)
		}
		result.Value = marshalledValue
	}

	return result, nil
}

var supportedExtensionTypes = []string{"integer", "boolean", "printable_string", "utf8_string"}

var extensionSchema *schema.Resource = &schema.Resource{
	Schema: map[string]*schema.Schema{
		"oid": {
			Type:         schema.TypeString,
			Description:  "The oid of the extension in dot format",
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.StringMatch(regexp.MustCompile(`\d+(\.\d+)*`), "Extension oid must use the dot notation"),
		},
		"critical": {
			Type:        schema.TypeBool,
			Description: "Whether the extension should be treated as critical",
			Optional:    true,
			Default:     false,
			ForceNew:    true,
		},
		"integer_value": {
			Type:        schema.TypeInt,
			Description: "Fill this field if the extension value should be encoded as an ASN.1 INTEGER",
			Optional:    true,
			ForceNew:    true,
		},
		"boolean_value": {
			Type:        schema.TypeBool,
			Description: "Fill this field if the extension value should be encoded as an ASN.1 BOOLEAN",
			Optional:    true,
			ForceNew:    true,
		},
		"printable_string_value": {
			Type:        schema.TypeString,
			Description: "Fill this field if the extension value should be encoded as an ASN.1 PrintableString",
			Optional:    true,
			ForceNew:    true,
		},
		"utf8_string_value": {
			Type:        schema.TypeString,
			Description: "Fill this field if the extension value should be encoded as an ASN.1 UTF8String",
			Optional:    true,
			ForceNew:    true,
		},
		"type": {
			Type:         schema.TypeString,
			Description:  "The type of the value. One of: " + strings.Join(supportedExtensionTypes[:], ", "),
			Required:     true,
			ForceNew:     true,
			ValidateFunc: validation.StringInSlice(supportedExtensionTypes[:], false),
		},
	},
}
