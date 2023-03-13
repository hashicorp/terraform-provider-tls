package provider

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"strings"
)

const defaultCipher = "AES256"

var supportedPEMCiphersMapping = map[string]x509.PEMCipher{
	"AES256": x509.PEMCipherAES256,
	"AES128": x509.PEMCipherAES128,
	"AES192": x509.PEMCipherAES192,
	"3DES":   x509.PEMCipher3DES,
}

func supportedPEMCiphers() (keys []string) {
	for key := range supportedPEMCiphersMapping {
		keys = append(keys, key)
	}
	return
}

type encryptedPEMResource struct{}

var _ resource.Resource = (*encryptedPEMResource)(nil)

func NewEncryptedPEMResource() resource.Resource {
	return &encryptedPEMResource{}
}

func (r *encryptedPEMResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_encrypted_pem"
}

func (r *encryptedPEMResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			// Required attributes
			"pem": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "A file in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},
			"password": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The password to encrypt the pem.",
			},

			// Optional attributes
			"cipher": schema.StringAttribute{
				Optional:  true,
				Sensitive: false,
				Computed:  true,
				Validators: []validator.String{
					stringvalidator.OneOf(supportedPEMCiphers()...),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
				Description: "The cipher that is used to encrypt the PEM file. " +
					"Defaults to " + defaultCipher + ". " +
					"Supported ciphers are: " +
					strings.Join(supportedPEMCiphers(), ","),
			},

			// Computed attributes
			"encrypted_pem": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				Description: "The input file in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format, " +
					"encrypted according to RFC 1432. " +
					"Note that encryption as specified in RFC 1423 is insecure by design. " +
					"Since it does not authenticate the ciphertext, " +
					"it is vulnerable to padding oracle attacks that can let an attacker recover the plaintext.",
			},
			"id": schema.StringAttribute{
				Computed: true,
				Description: "Unique identifier for this data source: " +
					"hexadecimal representation of the SHA1 checksum of the data source.",
			},
		},
		MarkdownDescription: "Encrypt a [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) according to the same RFC.",
	}
}

func (r *encryptedPEMResource) Create(ctx context.Context, req resource.CreateRequest, res *resource.CreateResponse) {
	tflog.Debug(ctx, "Reading PEM resource")

	var newState encryptedPemResourceModel
	res.Diagnostics.Append(req.Plan.Get(ctx, &newState)...)
	if res.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Loaded encrypted pem configuration", map[string]interface{}{
		"encryptedPemConfig": fmt.Sprintf("%+v", newState),
	})

	var err error

	var pemBlock *pem.Block
	if !newState.PEM.IsNull() && !newState.PEM.IsUnknown() {
		tflog.Debug(ctx, "Loading PEM file into struct")

		var rest []byte
		pemBytes := []byte(newState.PEM.ValueString())
		pemBlock, rest = pem.Decode(pemBytes)
		if pemBlock == nil {
			err = fmt.Errorf("failed to decode PEM block: decoded bytes %d, undecoded %d", len(pemBytes)-len(rest), len(rest))
		}
	}
	if err != nil {
		res.Diagnostics.AddError("Unable to load PEM file", err.Error())
		return
	}

	var pwd []byte
	if !newState.Password.IsNull() && !newState.Password.IsUnknown() {
		pwd = []byte(newState.Password.ValueString())
	}

	var pemCipher x509.PEMCipher
	if !newState.Cipher.IsNull() && !newState.Cipher.IsUnknown() {
		pemCipher = supportedPEMCiphersMapping[newState.Cipher.ValueString()]
	} else {
		pemCipher = supportedPEMCiphersMapping[defaultCipher]
		newState.Cipher = types.StringValue(defaultCipher)
	}

	//goland:noinspection GoDeprecation
	encryptedPEMBlock, err := x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, pwd, pemCipher)
	if err != nil {
		res.Diagnostics.AddError("Unable to encode the PEM block", err.Error())
		return
	}

	tflog.Debug(ctx, "Storing encrypted PEM into the state")
	encryptedPEMBytes := pem.EncodeToMemory(encryptedPEMBlock)
	encryptedPEM := string(encryptedPEMBytes)
	newState.EncryptedPEM = types.StringValue(encryptedPEM)

	idVal := fmt.Sprintf("%x", sha256.Sum256(encryptedPEMBytes))
	newState.ID = types.StringValue(idVal)

	tflog.Debug(ctx, "Storing encrypted pem info into the state")
	res.Diagnostics.Append(res.State.Set(ctx, newState)...)
}

func (r *encryptedPEMResource) Update(ctx context.Context, req resource.UpdateRequest, res *resource.UpdateResponse) {
	tflog.Debug(ctx, "Updating encrypted pem")

	updatedUsingPlan(ctx, &req, res, &encryptedPEMResource{})
	//if res.Diagnostics.HasError() {
	//	return
	//}
	//
	//var cipher types.String
	//res.Diagnostics.Append(res.State.GetAttribute(ctx, path.Root("cipher"), &cipher)...)
	//if res.Diagnostics.HasError() {
	//	return
	//}
	//
	//if cipher.IsNull() || cipher.IsUnknown() {
	//	cipher = types.StringValue(defaultCipher)
	//	res.Diagnostics.Append(res.State.SetAttribute(ctx, path.Root("cipher"), cipher)...)
	//}
}

func (r *encryptedPEMResource) Read(ctx context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// NO-OP: all there is to read is in the State, and response is already populated with that.
	tflog.Debug(ctx, "Reading encrypted pem from state")
}

func (r *encryptedPEMResource) Delete(ctx context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// NO-OP: Returning no error is enough for the framework to remove the resource from state.
	tflog.Debug(ctx, "Removing encrypted pem key from state")
}
