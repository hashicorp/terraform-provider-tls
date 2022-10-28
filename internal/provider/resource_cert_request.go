package provider

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/url"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

type certRequestResource struct{}

var _ resource.Resource = (*certRequestResource)(nil)

func NewCertRequestResource() resource.Resource {
	return &certRequestResource{}
}

func (r *certRequestResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_cert_request"
}

func (r *certRequestResource) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			// Required attributes
			"private_key_pem": {
				Type:     types.StringType,
				Required: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					requireReplaceIfStateContainsPEMString(),
				},
				Sensitive: true,
				Description: "Private key in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format, " +
					"that the certificate will belong to. " +
					"This can be read from a separate file using the [`file`](https://www.terraform.io/language/functions/file) " +
					"interpolation function. " +
					"Only an irreversible secure hash of the private key will be stored in the Terraform state.",
			},

			// Optional attributes
			"dns_names": {
				Type:     types.ListType{ElemType: types.StringType},
				Optional: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.RequiresReplace(),
				},
				Description: "List of DNS names for which a certificate is being requested (i.e. certificate subjects).",
			},
			"ip_addresses": {
				Type:     types.ListType{ElemType: types.StringType},
				Optional: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.RequiresReplace(),
				},
				Description: "List of IP addresses for which a certificate is being requested (i.e. certificate subjects).",
			},
			"uris": {
				Type:     types.ListType{ElemType: types.StringType},
				Optional: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.RequiresReplace(),
				},
				Description: "List of URIs for which a certificate is being requested (i.e. certificate subjects).",
			},

			// Computed attributes
			"key_algorithm": {
				Type:     types.StringType,
				Computed: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.UseStateForUnknown(),
				},
				Description: "Name of the algorithm used when generating the private key provided in `private_key_pem`. ",
			},
			"cert_request_pem": {
				Type:     types.StringType,
				Computed: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.UseStateForUnknown(),
				},
				Description: "The certificate request data in " +
					"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
					"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
					"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
					"value append a `\\n` at the end of the PEM. " +
					"In case this disrupts your use case, we recommend using " +
					"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
			},
			"id": {
				Type:     types.StringType,
				Computed: true,
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.UseStateForUnknown(),
				},
				Description: "Unique identifier for this resource: " +
					"hexadecimal representation of the SHA1 checksum of the resource.",
			},
		},
		Blocks: map[string]tfsdk.Block{
			"subject": {
				NestingMode: tfsdk.BlockNestingModeList,
				MinItems:    0,
				MaxItems:    1,
				// TODO Remove the validators below, once a fix for https://github.com/hashicorp/terraform-plugin-framework/issues/421 ships
				Validators: []tfsdk.AttributeValidator{
					listvalidator.SizeBetween(0, 1),
				},
				PlanModifiers: []tfsdk.AttributePlanModifier{
					resource.RequiresReplace(),
				},
				Attributes: map[string]tfsdk.Attribute{
					"organization": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `O`",
					},
					"common_name": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `CN`",
					},
					"organizational_unit": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `OU`",
					},
					"street_address": {
						Type: types.ListType{
							ElemType: types.StringType,
						},
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `STREET`",
					},
					"locality": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `L`",
					},
					"province": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `ST`",
					},
					"country": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `C`",
					},
					"postal_code": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `PC`",
					},
					"serial_number": {
						Type:     types.StringType,
						Optional: true,
						PlanModifiers: []tfsdk.AttributePlanModifier{
							resource.RequiresReplace(),
						},
						Description: "Distinguished name: `SERIALNUMBER`",
					},
				},
				MarkdownDescription: "The subject for which a certificate is being requested. " +
					"The acceptable arguments are all optional and their naming is based upon " +
					"[Issuer Distinguished Names (RFC5280)](https://tools.ietf.org/html/rfc5280#section-4.1.2.4) section.",
			},
		},
		MarkdownDescription: "Creates a Certificate Signing Request (CSR) in " +
			"[PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.\n\n" +
			"PEM is the typical format used to request a certificate from a Certificate Authority (CA).\n\n" +
			"This resource is intended to be used in conjunction with a Terraform provider " +
			"for a particular certificate authority in order to provision a new certificate.",
	}, nil
}

func (r *certRequestResource) Create(ctx context.Context, req resource.CreateRequest, res *resource.CreateResponse) {
	tflog.Debug(ctx, "Creating certificate request resource")

	// Load entire configuration into the model
	var newState certRequestResourceModel
	res.Diagnostics.Append(req.Plan.Get(ctx, &newState)...)
	if res.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Loaded certificate request configuration", map[string]interface{}{
		"certRequestConfig": fmt.Sprintf("%+v", newState),
	})

	// Parse the Private Key PEM
	tflog.Debug(ctx, "Parsing Private Key PEM")
	key, algorithm, err := parsePrivateKeyPEM([]byte(newState.PrivateKeyPEM.ValueString()))
	if err != nil {
		res.Diagnostics.AddError("Failed to parse private key PEM", err.Error())
		return
	}

	// Set the Algorithm of the Private Key
	tflog.Debug(ctx, "Detected key algorithm of private key", map[string]interface{}{
		"keyAlgorithm": algorithm,
	})
	newState.KeyAlgorithm = types.StringValue(algorithm.String())

	certReq := x509.CertificateRequest{}

	// Add a Subject if provided
	if !newState.Subject.IsNull() && !newState.Subject.IsUnknown() && len(newState.Subject.Elements()) > 0 {
		tflog.Debug(ctx, "Adding subject on certificate request", map[string]interface{}{
			"subject": newState.Subject,
		})

		subject := make([]certificateSubjectModel, 1)
		res.Diagnostics.Append(newState.Subject.ElementsAs(ctx, &subject, false)...)
		if res.Diagnostics.HasError() {
			return
		}

		certReq.Subject = createSubjectDistinguishedNames(ctx, subject[0])
	}

	// Add DNS names if provided
	if !newState.DNSNames.IsNull() && !newState.DNSNames.IsUnknown() {
		tflog.Debug(ctx, "Adding DNS names on certificate request", map[string]interface{}{
			"dnsNames": newState.DNSNames,
		})

		newState.DNSNames.ElementsAs(ctx, &certReq.DNSNames, false)
	}

	// Add IP addresses if provided
	if !newState.IPAddresses.IsNull() && !newState.IPAddresses.IsUnknown() {
		tflog.Debug(ctx, "Adding IP addresses on certificate request", map[string]interface{}{
			"ipAddresses": newState.IPAddresses,
		})

		for _, ipElem := range newState.IPAddresses.Elements() {
			ipStr := ipElem.(types.String).ValueString()
			ip := net.ParseIP(ipStr)
			if ip == nil {
				res.Diagnostics.AddError("Invalid IP address", fmt.Sprintf("Failed to parse %#v", ipStr))
				return
			}
			certReq.IPAddresses = append(certReq.IPAddresses, ip)
		}
	}

	// Add URIs if provided
	if !newState.URIs.IsNull() && !newState.URIs.IsUnknown() {
		tflog.Debug(ctx, "Adding URIs on certificate request", map[string]interface{}{
			"URIs": newState.URIs,
		})

		for _, uriElem := range newState.URIs.Elements() {
			uriStr := uriElem.(types.String).ValueString()
			uri, err := url.Parse(uriStr)
			if err != nil {
				res.Diagnostics.AddError("Invalid URI", fmt.Sprintf("Failed to parse %#v: %v", uriStr, err.Error()))
				return
			}
			certReq.URIs = append(certReq.URIs, uri)
		}
	}

	// Generate `Certificate Request`
	tflog.Debug(ctx, "Generating certificate request", map[string]interface{}{
		"certReq": certReq,
	})
	certReqBytes, err := x509.CreateCertificateRequest(rand.Reader, &certReq, key)
	if err != nil {
		res.Diagnostics.AddError("Error creating certificate request", err.Error())
		return
	}

	// Set `Certificate Request PEM` and `ID`
	newState.CertRequestPEM = types.StringValue(string(pem.EncodeToMemory(&pem.Block{Type: PreambleCertificateRequest.String(), Bytes: certReqBytes})))
	newState.ID = types.StringValue(hashForState(string(certReqBytes)))

	// Finally, set the state
	tflog.Debug(ctx, "Storing certificate request info into the state")
	res.Diagnostics.Append(res.State.Set(ctx, newState)...)
}

func (r *certRequestResource) Read(ctx context.Context, _ resource.ReadRequest, _ *resource.ReadResponse) {
	// NO-OP: all there is to read is in the State, and response is already populated with that.
	tflog.Debug(ctx, "Reading certificate request from state")
}

func (r *certRequestResource) Update(ctx context.Context, req resource.UpdateRequest, res *resource.UpdateResponse) {
	tflog.Debug(ctx, "Updating certificate request")

	updatedUsingPlan(ctx, &req, res, &certRequestResourceModel{})
}

func (r *certRequestResource) Delete(ctx context.Context, _ resource.DeleteRequest, _ *resource.DeleteResponse) {
	// NO-OP: Returning no error is enough for the framework to remove the resource from state.
	tflog.Debug(ctx, "Removing certificate request key from state")
}
