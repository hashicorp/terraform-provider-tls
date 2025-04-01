// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

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

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"golang.org/x/crypto/ssh"
)

var (
	_ ephemeral.EphemeralResource = (*privateKeyEphemeralResource)(nil)
)

type privateKeyEphemeralResource struct{}

func NewPrivateKeyEphemeralResource() ephemeral.EphemeralResource {
	return &privateKeyEphemeralResource{}
}

func (p *privateKeyEphemeralResource) Metadata(ctx context.Context, req ephemeral.MetadataRequest, resp *ephemeral.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_private_key"
}

func (p *privateKeyEphemeralResource) Schema(ctx context.Context, req ephemeral.SchemaRequest, resp *ephemeral.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			// Required attributes
			"algorithm": schema.StringAttribute{
				Required: true,
				Validators: []validator.String{
					stringvalidator.OneOf(supportedAlgorithmsStr()...),
				},
				Description: "Name of the algorithm to use when generating the private key. " +
					fmt.Sprintf("Currently-supported values are: `%s`. ", strings.Join(supportedAlgorithmsStr(), "`, `")),
			},

			// Optional attributes
			"rsa_bits": schema.Int64Attribute{
				Optional:            true,
				Computed:            true,
				MarkdownDescription: "When `algorithm` is `RSA`, the size of the generated RSA key, in bits (default: `2048`).",
			},
			"ecdsa_curve": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Validators: []validator.String{
					stringvalidator.OneOf(supportedECDSACurvesStr()...),
				},
				MarkdownDescription: "When `algorithm` is `ECDSA`, the name of the elliptic curve to use. " +
					fmt.Sprintf("Currently-supported values are: `%s`. ", strings.Join(supportedECDSACurvesStr(), "`, `")) +
					fmt.Sprintf("(default: `%s`).", P224.String()),
			},

			// Computed attributes
			"private_key_pem": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},
			"private_key_openssh": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key data in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) format.",
			},
			"private_key_pem_pkcs8": schema.StringAttribute{
				Computed:            true,
				Sensitive:           true,
				MarkdownDescription: "Private key data in [PKCS#8 PEM (RFC 5208)](https://datatracker.ietf.org/doc/html/rfc5208) format.",
			},
			"public_key_pem": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "Public key data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},
			"public_key_openssh": schema.StringAttribute{
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
			"public_key_fingerprint_md5": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The fingerprint of the public key data in OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations).",
			},
			"public_key_fingerprint_sha256": schema.StringAttribute{
				Computed: true,
				MarkdownDescription: "The fingerprint of the public key data in OpenSSH SHA256 hash format, e.g. `SHA256:...`. " +
					"Only available if the selected private key format is compatible, similarly to " +
					"`public_key_openssh` and the [ECDSA P224 limitations](../../docs#limitations).",
			},
		},
		MarkdownDescription: "Creates a PEM (and OpenSSH) formatted private key.\n\n" +
			"Generates a secure private key and encodes it in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) and " +
			"[OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) formats. " +
			"This resource is primarily intended for easily bootstrapping throwaway development environments.",
	}
}

func (p *privateKeyEphemeralResource) Open(ctx context.Context, req ephemeral.OpenRequest, res *ephemeral.OpenResponse) {
	tflog.Debug(ctx, "Creating private key resource")

	// Load entire configuration into the model
	data := new(privateKeyEphemeralModel)
	res.Diagnostics.Append(req.Config.Get(ctx, data)...)
	if res.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Loaded private key configuration", map[string]interface{}{
		"privateKeyConfig": fmt.Sprintf("%+v", *data),
	})

	data.setupDefaultValue()

	keyAlgoName := Algorithm(data.Algorithm.ValueString())

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
	resData := data.toResourceModel()
	prvKey, err := keyGen(&resData)
	if err != nil {
		res.Diagnostics.AddError("Unable to generate Key from configuration", err.Error())
		return
	}
	data = resData.toEphemeralModel()

	// Marshal the Key in PEM block
	tflog.Debug(ctx, "Marshalling private key to PEM")
	var prvKeyPemBlock *pem.Block
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

	// Marshal the Key in PKCS#8 PEM block
	tflog.Debug(ctx, "Marshalling private key to PKCS#8 PEM")
	prvKeyPKCS8PemBlock, err := prvKeyToPKCS8PEMBlock(prvKey)
	if err != nil {
		res.Diagnostics.AddError("Unable to encode private key to PKCS#8 PEM", err.Error())
		return
	}

	data.PrivateKeyPem = types.StringValue(string(pem.EncodeToMemory(prvKeyPemBlock)))
	data.PrivateKeyPKCS8 = types.StringValue(string(pem.EncodeToMemory(prvKeyPKCS8PemBlock)))

	// Marshal the Key in OpenSSH PEM block, if supported
	tflog.Debug(ctx, "Marshalling private key to OpenSSH PEM (if supported)")
	data.PrivateKeyOpenSSH = types.StringValue("")
	if prvKeySupportsOpenSSHMarshalling(prvKey) {
		openSSHKeyPemBlock, err := ssh.MarshalPrivateKey(prvKey, "")
		if err != nil {
			res.Diagnostics.AddError("Unable to marshal private key into OpenSSH format", err.Error())
			return
		}

		data.PrivateKeyOpenSSH = types.StringValue(string(pem.EncodeToMemory(openSSHKeyPemBlock)))
	}

	// Store the model populated so far, onto the State
	// Store the rest of the "public key" attributes onto the State
	tflog.Debug(ctx, "Storing private key's public key info")
	res.Diagnostics.Append(data.setPublicKeyAttributes(prvKey)...)
	tflog.Debug(ctx, "Storing private key info into the state")
	res.Diagnostics.Append(res.Result.Set(ctx, data)...)
	if res.Diagnostics.HasError() {
		return
	}

}
