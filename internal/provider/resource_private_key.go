package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/hashicorp/terraform-provider-tls/internal/openssh"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/attribute_plan_modification"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/attribute_validation"
)

type (
	privateKeyResourceType struct{}
	privateKeyResource     struct{}
)

var (
	_ tfsdk.ResourceType = (*privateKeyResourceType)(nil)
	_ tfsdk.Resource     = (*privateKeyResource)(nil)
)

func (rt *privateKeyResourceType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			// Required attributes
			"algorithm": {
				Type:     types.StringType,
				Required: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.RequiresReplace(),
				},
				Validators: []tfsdk.AttributeValidator{
					attribute_validation.OneOf(supportedAlgorithmsAttrValue()...),
				},
				Description: "Name of the algorithm to use when generating the private key. " +
					fmt.Sprintf("Currently-supported values are: `%s`. ", strings.Join(supportedAlgorithmsStr(), "`, `")),
			},

			// Optional attributes
			"rsa_bits": {
				Type:     types.Int64Type,
				Optional: true,
				Computed: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.RequiresReplace(),
					attribute_plan_modification.DefaultValue(types.Int64{Value: 2048}),
				},
				MarkdownDescription: "When `algorithm` is `RSA`, the size of the generated RSA key, in bits (default: `2048`).",
			},
			"ecdsa_curve": {
				Type:     types.StringType,
				Optional: true,
				Computed: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					tfsdk.RequiresReplace(),
					attribute_plan_modification.DefaultValue(types.String{Value: P224.String()}),
				},
				Validators: []tfsdk.AttributeValidator{
					attribute_validation.OneOf(supportedECDSACurvesAttrValue()...),
				},
				MarkdownDescription: "When `algorithm` is `ECDSA`, the name of the elliptic curve to use. " +
					fmt.Sprintf("Currently-supported values are: `%s`. ", strings.Join(supportedECDSACurvesStr(), "`, `")) +
					fmt.Sprintf("(default: `%s`).", P224.String()),
			},

			// Computed attributes
			"private_key_pem": {
				Type:                types.StringType,
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},
			"private_key_openssh": {
				Type:                types.StringType,
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key data in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format.",
			},
			"public_key_pem": {
				Type:     types.StringType,
				Computed: true,
				MarkdownDescription: "Public key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},
			"public_key_openssh": {
				Type:     types.StringType,
				Computed: true,
				MarkdownDescription: " The public key data in " +
					"[\"Authorized Keys\"](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file) format. " +
					"This is not populated for `ECDSA` with curve `P224`, as it is [not supported](../../docs#limitations). " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},
			"public_key_fingerprint_md5": {
				Type:     types.StringType,
				Computed: true,
				MarkdownDescription: "The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations).",
			},
			"public_key_fingerprint_sha256": {
				Type:     types.StringType,
				Computed: true,
				MarkdownDescription: "The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations).",
			},
			"id": {
				Type:     types.StringType,
				Computed: true,
				MarkdownDescription: "Unique identifier for this resource: " +
					"hexadecimal representation of the SHA1 checksum of the resource.",
			},
		},
		MarkdownDescription: "Creates a PEM (and OpenSSH) formatted private key.\n\n" +
			"Generates a secure private key and encodes it in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) and " +
			"[OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) formats. " +
			"This resource is primarily intended for easily bootstrapping throwaway development environments.",
	}, nil
}

func (rt *privateKeyResourceType) NewResource(_ context.Context, _ tfsdk.Provider) (tfsdk.Resource, diag.Diagnostics) {
	return &privateKeyResource{}, nil
}

func (r *privateKeyResource) Create(ctx context.Context, req tfsdk.CreateResourceRequest, res *tfsdk.CreateResourceResponse) {
	tflog.Debug(ctx, "Creating private key resource")

	// Load entire configuration into the model
	var newState privateKeyResourceModel
	res.Diagnostics.Append(req.Plan.Get(ctx, &newState)...)
	if res.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Loaded private key configuration", map[string]interface{}{
		"privateKeyConfig": fmt.Sprintf("%+v", newState),
	})

	keyAlgoName := Algorithm(newState.Algorithm.Value)

	// Identify the correct (Private) Key Generator
	var keyGen keyGenerator
	var ok bool
	if keyGen, ok = keyGenerators[keyAlgoName]; !ok {
		res.Diagnostics.AddError("Invalid Key Algorithm", fmt.Sprintf("Key Algorithm %q is not supported", keyAlgoName))
		return
	}

	// Generate the new Key
	tflog.Debug(ctx, "Generating private key for algorithm", map[string]interface{}{
		"algorithm": keyAlgoName,
	})
	prvKey, err := keyGen(&newState)
	if err != nil {
		res.Diagnostics.AddError("Unable to generate Key from configuration", err.Error())
		return
	}

	// Marshal the Key in PEM block
	tflog.Debug(ctx, "Marshalling private key to PEM")
	var prvKeyPemBlock *pem.Block
	doMarshalOpenSSHKeyPemBlock := true
	switch k := prvKey.(type) {
	case *rsa.PrivateKey:
		prvKeyPemBlock = &pem.Block{
			Type:  PreamblePrivateKeyRSA.String(),
			Bytes: x509.MarshalPKCS1PrivateKey(k),
		}
	case *ecdsa.PrivateKey:
		keyBytes, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			res.Diagnostics.AddError("Unable to encode key to PEM", err.Error())
			return
		}

		prvKeyPemBlock = &pem.Block{
			Type:  PreamblePrivateKeyEC.String(),
			Bytes: keyBytes,
		}

		// GOTCHA: `x/crypto/ssh` doesn't handle elliptic curve P-224
		if k.Curve.Params().Name == "P-224" {
			doMarshalOpenSSHKeyPemBlock = false
		}
	case ed25519.PrivateKey:
		prvKeyBytes, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			res.Diagnostics.AddError("Unable to encode key to PEM", err.Error())
			return
		}

		prvKeyPemBlock = &pem.Block{
			Type:  PreamblePrivateKeyPKCS8.String(),
			Bytes: prvKeyBytes,
		}
	default:
		res.Diagnostics.AddError("Unsupported private key type", fmt.Sprintf("Key type %T not supported", prvKey))
		return
	}

	newState.PrivateKeyPem = types.String{Value: string(pem.EncodeToMemory(prvKeyPemBlock))}

	// Marshal the Key in OpenSSH PEM block, if enabled
	tflog.Debug(ctx, "Marshalling private key to OpenSSH PEM")
	prvKeyOpenSSH := ""
	if doMarshalOpenSSHKeyPemBlock {
		openSSHKeyPemBlock, err := openssh.MarshalPrivateKey(prvKey, "")
		if err != nil {
			res.Diagnostics.AddError("Unable to marshal private key into OpenSSH format", err.Error())
			return
		}

		prvKeyOpenSSH = string(pem.EncodeToMemory(openSSHKeyPemBlock))
	}
	newState.PrivateKeyOpenSSH = types.String{Value: prvKeyOpenSSH}

	// Store the model populated so far, onto the State
	tflog.Debug(ctx, "Storing private key info into the state")
	res.Diagnostics.Append(res.State.Set(ctx, newState)...)
	if res.Diagnostics.HasError() {
		return
	}

	// Store the rest of the "public key" attributes onto the State
	tflog.Debug(ctx, "Storing private key's public key info into the state")
	res.Diagnostics.Append(setPublicKeyAttributes(ctx, &res.State, prvKey)...)
}

func (r *privateKeyResource) Read(ctx context.Context, _ tfsdk.ReadResourceRequest, _ *tfsdk.ReadResourceResponse) {
	// NO-OP: all there is to read is in the State, and response is already populated with that.
	tflog.Debug(ctx, "Reading private key from state")
}

func (r *privateKeyResource) Update(_ context.Context, _ tfsdk.UpdateResourceRequest, _ *tfsdk.UpdateResourceResponse) {
	// NO-OP: changes to this resource will force a "re-create".
}

func (r *privateKeyResource) Delete(ctx context.Context, _ tfsdk.DeleteResourceRequest, _ *tfsdk.DeleteResourceResponse) {
	// NO-OP: Returning no error is enough for the framework to remove the resource from state.
	tflog.Debug(ctx, "Removing private key from state")
}
