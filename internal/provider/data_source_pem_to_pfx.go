// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// Define the PFX data source struct
type pemDataSource struct {
	provider *tlsProvider
}

var _ datasource.DataSource = (*pemDataSource)(nil)

// New PFX Data Source
func NewPemToPfxDataSource() datasource.DataSource {
	return &pemDataSource{}
}

// Metadata for the PFX Data Source
func (d *pemDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_pem_to_pfx"
}

// Configure method for the PEM Data Source
func (d *pemDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.provider, resp.Diagnostics = toProvider(req.ProviderData)
}

func (d *pemDataSource) Schema(_ context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"certificate_pem": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Certificate or certificate chain in pem format",
			},
			"private_key_pem": schema.StringAttribute{
				Required:    true,
				Sensitive:   true,
				Description: "Private Key in pem format",
			},
			"password_pem": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "password for private key in pem format",
			},
			"password_pfx": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "password for pfx certificate",
			},
			"certificate_pfx": schema.StringAttribute{
				Computed:    true,
				Description: "Generated PFX data base64 encoded",
			},
		},
		MarkdownDescription: `
Converts a PEM certificate and private key into a PFX file. Encrypted PEM can be used if password_pem is given and the resulting PFX file can also be encrypted if password_pfx is given
Note:
Using modern encoding type which support advanced algorithms like AES256 encryption for securimng private keys to encrypt PFX certicate
Using rand.Reader to derive encryption keys from passwords but as per GO community, password encrypted pfx are not completely secure and can be broken`,
	}
}

// Read fetches the certificates either from a URL or from provided content and populates the state.
func (ds *pemDataSource) Read(ctx context.Context, req datasource.ReadRequest, res *datasource.ReadResponse) {
	tflog.Debug(ctx, "Creating PEM to PFX resource")

	// Load entire configuration into the model
	var newState PemToPfxDataSourceModel
	res.Diagnostics.Append(req.Config.Get(ctx, &newState)...)
	if res.Diagnostics.HasError() {
		return
	}

	tflog.Debug(ctx, "Loaded PEM to PFX configuration", map[string]interface{}{
		"pemToPfxConfig": fmt.Sprintf("%+v", newState),
	})

	CertPem := newState.CertPem.ValueString()
	tflog.Debug(ctx, "Certificate PEM", map[string]interface{}{
		"cert_pem": []byte(CertPem),
	})

	PrivateKeyPem := newState.PrivateKeyPem.ValueString()
	tflog.Debug(ctx, "Private Key PEM", map[string]interface{}{
		"private_key_pem": []byte(PrivateKeyPem),
	})

	// Combine both PEM strings
	pemData := []byte(CertPem + "\n" + PrivateKeyPem)

	pemPassword := newState.PrivateKeyPass.ValueString()
	pfxPassword := newState.PfxPassword.ValueString()

	pkcs12Data, _ := ConvertPemToPkcs12([]byte(pemData), pemPassword, pfxPassword)

	// Set PFX data and ID in the new state
	newState.CertPfx = types.StringValue(base64.StdEncoding.EncodeToString(pkcs12Data))

	// Set the final state
	tflog.Debug(ctx, "Storing PEM to PFX info into the state")
	res.Diagnostics.Append(res.State.Set(ctx, newState)...)
}
