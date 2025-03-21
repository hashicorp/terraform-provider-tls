// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type providerConfigModel struct {
	Proxy types.List `tfsdk:"proxy"` //< providerProxyConfigModel
}

type providerProxyConfigModel struct {
	URL      types.String `tfsdk:"url"`
	Username types.String `tfsdk:"username"`
	Password types.String `tfsdk:"password"`
	FromEnv  types.Bool   `tfsdk:"from_env"`
}

type certificateDataSourceModel struct {
	URL          types.String `tfsdk:"url"`
	Content      types.String `tfsdk:"content"`
	VerifyChain  types.Bool   `tfsdk:"verify_chain"`
	Certificates types.List   `tfsdk:"certificates"` //< CertificateModel
	ID           types.String `tfsdk:"id"`
}

type CertificateModel struct {
	SignatureAlgorithm types.String `tfsdk:"signature_algorithm"`
	PublicKeyAlgorithm types.String `tfsdk:"public_key_algorithm"`
	SerialNumber       types.String `tfsdk:"serial_number"`
	IsCA               types.Bool   `tfsdk:"is_ca"`
	MaxPathLen         types.Int64  `tfsdk:"max_path_length"`
	Version            types.Int64  `tfsdk:"version"`
	Issuer             types.String `tfsdk:"issuer"`
	Subject            types.String `tfsdk:"subject"`
	NotBefore          types.String `tfsdk:"not_before"`
	NotAfter           types.String `tfsdk:"not_after"`
	SHA1Fingerprint    types.String `tfsdk:"sha1_fingerprint"`
	CertPEM            types.String `tfsdk:"cert_pem"`
}

type certRequestResourceModel struct {
	DNSNames       types.List   `tfsdk:"dns_names"`
	IPAddresses    types.List   `tfsdk:"ip_addresses"`
	URIs           types.List   `tfsdk:"uris"`
	PrivateKeyPEM  types.String `tfsdk:"private_key_pem"`
	KeyAlgorithm   types.String `tfsdk:"key_algorithm"`
	CertRequestPEM types.String `tfsdk:"cert_request_pem"`
	Subject        types.List   `tfsdk:"subject"` //< certificateSubjectModel
	ID             types.String `tfsdk:"id"`
}

type certificateSubjectModel struct {
	Organization       types.String `tfsdk:"organization"`
	CommonName         types.String `tfsdk:"common_name"`
	OrganizationalUnit types.String `tfsdk:"organizational_unit"`
	StreetAddress      types.List   `tfsdk:"street_address"`
	Locality           types.String `tfsdk:"locality"`
	Province           types.String `tfsdk:"province"`
	Country            types.String `tfsdk:"country"`
	PostalCode         types.String `tfsdk:"postal_code"`
	SerialNumber       types.String `tfsdk:"serial_number"`
}

type privateKeyResourceModel struct {
	Algorithm                  types.String `tfsdk:"algorithm"`
	RSABits                    types.Int64  `tfsdk:"rsa_bits"`
	ECDSACurve                 types.String `tfsdk:"ecdsa_curve"`
	PrivateKeyPem              types.String `tfsdk:"private_key_pem"`
	PrivateKeyOpenSSH          types.String `tfsdk:"private_key_openssh"`
	PrivateKeyPKCS8            types.String `tfsdk:"private_key_pem_pkcs8"`
	PublicKeyPem               types.String `tfsdk:"public_key_pem"`
	PublicKeyOpenSSH           types.String `tfsdk:"public_key_openssh"`
	PublicKeyFingerprintMD5    types.String `tfsdk:"public_key_fingerprint_md5"`
	PublicKeyFingerprintSHA256 types.String `tfsdk:"public_key_fingerprint_sha256"`
	ID                         types.String `tfsdk:"id"`
}

type selfSignedCertResourceModel struct {
	PrivateKeyPEM                               types.String `tfsdk:"private_key_pem"`
	DNSNames                                    types.List   `tfsdk:"dns_names"`
	IPAddresses                                 types.List   `tfsdk:"ip_addresses"`
	URIs                                        types.List   `tfsdk:"uris"`
	Subject                                     types.List   `tfsdk:"subject"` //< certificateSubjectModel
	ValidityPeriodHours                         types.Int64  `tfsdk:"validity_period_hours"`
	AllowedUses                                 types.List   `tfsdk:"allowed_uses"`
	EarlyRenewalHours                           types.Int64  `tfsdk:"early_renewal_hours"`
	IsCACertificate                             types.Bool   `tfsdk:"is_ca_certificate"`
	NamedKeyConstraintPermittedDnsNamesCritical types.Bool   `tfsdk:"name_constraint_permitted_dns_names_critical"`
	NamedKeyConstraintPermittedDnsNames         types.List   `tfsdk:"name_constraint_permitted_dns_names"`
	NamedKeyConstraintExcludedDnsNames          types.List   `tfsdk:"name_constraint_excluded_dns_names"`
	MaxPathLen                                  types.Int64  `tfsdk:"max_path_length"`
	SetSubjectKeyID                             types.Bool   `tfsdk:"set_subject_key_id"`
	SetAuthorityKeyID                           types.Bool   `tfsdk:"set_authority_key_id"`
	CertPEM                                     types.String `tfsdk:"cert_pem"`
	ReadyForRenewal                             types.Bool   `tfsdk:"ready_for_renewal"`
	ValidityStartTime                           types.String `tfsdk:"validity_start_time"`
	ValidityEndTime                             types.String `tfsdk:"validity_end_time"`
	KeyAlgorithm                                types.String `tfsdk:"key_algorithm"`
	ID                                          types.String `tfsdk:"id"`
}

type locallySignedCertResourceModel struct {
	CACertPEM                                   types.String `tfsdk:"ca_cert_pem"`
	CAPrivateKeyPEM                             types.String `tfsdk:"ca_private_key_pem"`
	CertRequestPEM                              types.String `tfsdk:"cert_request_pem"`
	ValidityPeriodHours                         types.Int64  `tfsdk:"validity_period_hours"`
	AllowedUses                                 types.List   `tfsdk:"allowed_uses"`
	EarlyRenewalHours                           types.Int64  `tfsdk:"early_renewal_hours"`
	IsCACertificate                             types.Bool   `tfsdk:"is_ca_certificate"`
	NamedKeyConstraintPermittedDnsNamesCritical types.Bool   `tfsdk:"name_constraint_permitted_dns_names_critical"`
	NamedKeyConstraintPermittedDnsNames         types.List   `tfsdk:"name_constraint_permitted_dns_names"`
	NamedKeyConstraintExcludedDnsNames          types.List   `tfsdk:"name_constraint_excluded_dns_names"`
	MaxPathLen                                  types.Int64  `tfsdk:"max_path_length"`
	SetSubjectKeyID                             types.Bool   `tfsdk:"set_subject_key_id"`
	SetAuthorityKeyID                           types.Bool   `tfsdk:"set_authority_key_id"`
	CertPEM                                     types.String `tfsdk:"cert_pem"`
	ReadyForRenewal                             types.Bool   `tfsdk:"ready_for_renewal"`
	ValidityStartTime                           types.String `tfsdk:"validity_start_time"`
	ValidityEndTime                             types.String `tfsdk:"validity_end_time"`
	CAKeyAlgorithm                              types.String `tfsdk:"ca_key_algorithm"`
	ID                                          types.String `tfsdk:"id"`
}

// Model for the state of the PFX data source.
type PfxToPemDataSourceModel struct {
	ContentBase64   types.String `tfsdk:"content_base64"`
	PrivateKeyPass  types.String `tfsdk:"password_pem"` // Private Key password
	PfxPassword     types.String `tfsdk:"password_pfx"` // Keystore password
	CertificatesPem types.List   `tfsdk:"certificates_pem"`
	PrivateKeysPem  types.List   `tfsdk:"private_keys_pem"`
}

// Model for the state of the PEM data source.
type PemToPfxDataSourceModel struct {
	CertPem        types.String `tfsdk:"certificate_pem"` // Certificate or certificate chain
	PrivateKeyPem  types.String `tfsdk:"private_key_pem"` // Private Key
	PrivateKeyPass types.String `tfsdk:"password_pem"`    // Private Key password
	PfxPassword    types.String `tfsdk:"password_pfx"`    // Keystore password
	CertPfx        types.String `tfsdk:"certificate_pfx"` // Generated PFX data
}
