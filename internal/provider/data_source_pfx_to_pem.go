// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Define the PFX data source struct.
type pfxDataSource struct {
	provider *tlsProvider
}

var _ datasource.DataSource = (*pfxDataSource)(nil)

// New PFX Data Source.
func NewPfxToPemDataSource() datasource.DataSource {
	return &pfxDataSource{}
}

// Metadata for the PFX Data Source.
func (d *pfxDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pfx_to_pem"
}

// Configure method for the PFX Data Source.
func (d *pfxDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.provider, resp.Diagnostics = toProvider(req.ProviderData)
}

// Implement the Schema method.
func (d *pfxDataSource) Schema(_ context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"content_base64": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "Contents of PFX certificate in base64 encoded string",
			},
			"password_pfx": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "password for pfx certificate",
			},
			"password_pem": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "password for private key in pem format",
			},
			"certificates_pem": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				MarkdownDescription: "List of certificates in PEM format.",
			},
			"private_keys_pem": schema.ListAttribute{
				ElementType:         types.StringType,
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "List of private keys in PEM format.",
			},
		},
		MarkdownDescription: `
Convert PFX certificate to PEM format.

Note:
- PEM files are generated in PKCS#8 format, which is a generalized format for private keys that supports all algorithm types.
- Supported algorithm types include:
	- RSA
	- DSA
	- ECDSA
	- Elliptic Curve keys
	- EdDSA
- PKCS#8 format includes a field to specify the algorithm used for encryption, making it algorithm-agnostic.
- PKCS#1 is a legacy key format, specifically designed for a limited set of algorithm types in the context of modern cryptographic practices.`,
	}
}

// Read method for the PFX Data Source.
func (d *pfxDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var state PfxToPemDataSourceModel

	// Get the current state from the config
	resp.Diagnostics.Append(req.Config.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	pfxData, err := base64Decode([]byte(state.ContentBase64.ValueString()))
	if err != nil {
		resp.Diagnostics.AddError("Failed to base64 decode", err.Error())
		return
	}

	pemPassword := state.PrivateKeyPass.ValueString()
	pfxPassword := state.PfxPassword.ValueString()

	pemData, err := ConvertPkcs12ToPem(pfxData, pfxPassword, pemPassword)
	if err != nil {
		resp.Diagnostics.AddError("Failed to decode PFX data", err.Error())
		return
	}
	fmt.Println("Successfully converted PFX to PEM data.")

	//Process the PEM blocks for certificates and private keys
	var (
		certificatesPEM []string
		privateKeysPEM  []string
	)

	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break // No more PEM blocks
		}

		// Separate based on block type
		if block.Type == "CERTIFICATE" {
			certificatesPEM = append(certificatesPEM, string(pem.EncodeToMemory(block)))
		} else if block.Type == "PRIVATE KEY" {
			privateKeysPEM = append(privateKeysPEM, string(pem.EncodeToMemory(block)))
		}

		// Update the buffer to process remaining data
		pemData = bytes.NewBuffer(rest).Bytes()
	}

	// Convert slices to types.List
	certificatesList, diagCertificates := types.ListValueFrom(ctx, types.StringType, certificatesPEM)
	privateKeysList, diagPrivateKeys := types.ListValueFrom(ctx, types.StringType, privateKeysPEM)

	// Check for diagnostics (errors) during the conversion
	if diagCertificates.HasError() || diagPrivateKeys.HasError() {
		resp.Diagnostics.Append(diagCertificates...)
		resp.Diagnostics.Append(diagPrivateKeys...)
		return
	}

	// Assign the converted lists to the model
	state.CertificatesPem = certificatesList
	state.PrivateKeysPem = privateKeysList

	// Set the final state
	resp.Diagnostics.Append(resp.State.Set(ctx, state)...)
	if resp.Diagnostics.HasError() {
		return
	}

}
