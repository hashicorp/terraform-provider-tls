// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type publicKeyResource struct{}

var _ resource.Resource = (*publicKeyResource)(nil)

func NewPublicKeyResource() resource.Resource {
	return &publicKeyResource{}
}

func (r *publicKeyResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_public_key"
}

func (r *publicKeyResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Version: 0,
		Attributes: map[string]schema.Attribute{
			// Write-only inputs (mutually exclusive)
			"private_key_pem_wo": schema.StringAttribute{
				Optional:  true,
				WriteOnly: true,
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("private_key_pem_wo"),
						path.MatchRoot("private_key_openssh_wo"),
					),
				},
				Description: "The private key (in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format) " +
					"to extract the public key from. " +
					"This is _mutually exclusive_ with `private_key_openssh_wo`. " +
					"This attribute is write-only and will not be stored in state. " +
					fmt.Sprintf("Currently-supported algorithms for keys are: `%s`. ", strings.Join(supportedAlgorithmsStr(), "`, `")),
			},
			"private_key_openssh_wo": schema.StringAttribute{
				Optional:  true,
				WriteOnly: true,
				Validators: []validator.String{
					stringvalidator.ExactlyOneOf(
						path.MatchRoot("private_key_pem_wo"),
						path.MatchRoot("private_key_openssh_wo"),
					),
				},
				Description: "The private key (in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format) " +
					"to extract the public key from. " +
					"This is _mutually exclusive_ with `private_key_pem_wo`. " +
					"This attribute is write-only and will not be stored in state. " +
					fmt.Sprintf("Currently-supported algorithms for keys are: `%s`. ", strings.Join(supportedAlgorithmsStr(), "`, `")),
			},

			// Version tracking
			"private_key_wo_version": schema.Int64Attribute{
				Optional: true,
				PlanModifiers: []planmodifier.Int64{
					int64planmodifier.RequiresReplace(),
				},
				Description: "A version number that, when changed, triggers replacement of this resource, " +
					"causing the write-only private key to be re-read from config. " +
					"This is useful when the private key changes, since write-only attributes " +
					"are not tracked in state.",
			},

			// Computed outputs
			"algorithm": schema.StringAttribute{
				Computed: true,
				Description: "The name of the algorithm used by the given private key. " +
					fmt.Sprintf("Possible values are: `%s`. ", strings.Join(supportedAlgorithmsStr(), "`, `")),
			},
			"public_key_pem": schema.StringAttribute{
				Computed: true,
				Description: "The public key, in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},
			"public_key_openssh": schema.StringAttribute{
				Computed: true,
				Description: "The public key, in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format. " +
					"This is also known as ['Authorized Keys'](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. " +
					"This is not populated for `ECDSA` with curve `P224`, as it is [not supported](../../docs#limitations). " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},
			"public_key_fingerprint_md5": schema.StringAttribute{
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. " +
					"Only available if the selected private key format is compatible, as per the rules for " +
					"`public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations).",
			},
			"public_key_fingerprint_sha256": schema.StringAttribute{
				Computed: true,
				Description: "The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. " +
					"Only available if the selected private key format is compatible, as per the rules for " +
					"`public_key_openssh` and [ECDSA P224 limitations](../../docs#limitations).",
			},
			"id": schema.StringAttribute{
				Computed: true,
				Description: "Unique identifier for this resource: " +
					"hexadecimal representation of the SHA1 checksum of the resource.",
			},
		},
		MarkdownDescription: "Get a public key from a PEM-encoded private key.\n\n" +
			"Use this managed resource to get the public key from a [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) " +
			"or [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) formatted private key, " +
			"for use in other resources. The private key inputs use write-only attributes (Terraform 1.11+) " +
			"so the private key is never stored in plan or state.",
	}
}

func (r *publicKeyResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	tflog.Debug(ctx, "Creating public key resource")

	var prvKey crypto.PrivateKey
	var algorithm Algorithm
	var err error

	// Write-only attributes must be read from Config, not Plan,
	// since the framework nullifies write-only values in plan/state.
	var prvKeyArg types.String
	if req.Config.GetAttribute(ctx, path.Root("private_key_pem_wo"), &prvKeyArg); !prvKeyArg.IsNull() && !prvKeyArg.IsUnknown() {
		tflog.Debug(ctx, "Parsing private key from PEM")
		prvKey, algorithm, err = parsePrivateKeyPEM([]byte(prvKeyArg.ValueString()))
	} else if req.Config.GetAttribute(ctx, path.Root("private_key_openssh_wo"), &prvKeyArg); !prvKeyArg.IsNull() && !prvKeyArg.IsUnknown() {
		tflog.Debug(ctx, "Parsing private key from OpenSSH PEM")
		prvKey, algorithm, err = parsePrivateKeyOpenSSHPEM([]byte(prvKeyArg.ValueString()))
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to parse private key", err.Error())
		return
	}

	// Store private_key_wo_version from config into state
	var woVersion types.Int64
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("private_key_wo_version"), &woVersion)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("private_key_wo_version"), woVersion)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set algorithm
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("algorithm"), &algorithm)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Set all public key outputs
	resp.Diagnostics.Append(setPublicKeyAttributes(ctx, &resp.State, prvKey)...)
}

func (r *publicKeyResource) Read(ctx context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// NO-OP: all there is to read is in the State, and response is already populated with that.
	tflog.Debug(ctx, "Reading public key from state")
}

func (r *publicKeyResource) Update(_ context.Context, _ resource.UpdateRequest, _ *resource.UpdateResponse) {
	// NO-OP: changes to private_key_wo_version will force a "re-create" via RequiresReplace.
}

func (r *publicKeyResource) Delete(ctx context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// NO-OP: Returning no error is enough for the framework to remove the resource from state.
	tflog.Debug(ctx, "Removing public key from state")
}
