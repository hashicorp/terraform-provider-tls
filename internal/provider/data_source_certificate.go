package provider

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/hashicorp/terraform-provider-tls/internal/provider/attribute_validation"
)

type (
	certificateDataSourceType struct{}
	certificateDataSource     struct {
		provider *provider
	}
)

var (
	_ tfsdk.DataSourceType = (*certificateDataSourceType)(nil)
	_ tfsdk.DataSource     = (*certificateDataSource)(nil)
)

func (dst *certificateDataSourceType) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			// Required attributes
			"url": {
				Type:     types.StringType,
				Optional: true,
				Validators: []tfsdk.AttributeValidator{
					attribute_validation.UrlWithScheme(supportedURLSchemesStr()...),
					attribute_validation.ExactlyOneOf(
						tftypes.NewAttributePath().WithAttributeName("content"),
						tftypes.NewAttributePath().WithAttributeName("url"),
					),
				},
				MarkdownDescription: "URL of the endpoint to get the certificates from. " +
					fmt.Sprintf("Accepted schemes are: `%s`. ", strings.Join(supportedURLSchemesStr(), "`, `")) +
					"For scheme `https://` it will use the HTTP protocol and apply the `proxy` configuration " +
					"of the provider, if set. For scheme `tls://` it will instead use a secure TCP socket.",
			},
			"content": {
				Type:     types.StringType,
				Optional: true,
				Validators: []tfsdk.AttributeValidator{
					attribute_validation.ExactlyOneOf(
						tftypes.NewAttributePath().WithAttributeName("content"),
						tftypes.NewAttributePath().WithAttributeName("url"),
					),
				},
				MarkdownDescription: "The content of the certificate in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format.",
			},

			// Optional attributes
			"verify_chain": {
				Type:     types.BoolType,
				Optional: true,
				//Default:       true,
				Validators: []tfsdk.AttributeValidator{
					attribute_validation.ConflictsWith(
						tftypes.NewAttributePath().WithAttributeName("content"),
					),
				},
				MarkdownDescription: "Whether to verify the certificate chain while parsing it or not (default: `true`).",
			},

			// Computed attributes
			"certificates": {
				Computed: true,
				Attributes: tfsdk.ListNestedAttributes(map[string]tfsdk.Attribute{
					"signature_algorithm": {
						Type:                types.StringType,
						Computed:            true,
						MarkdownDescription: "The algorithm used to sign the certificate.",
					},
					"public_key_algorithm": {
						Type:                types.StringType,
						Computed:            true,
						MarkdownDescription: "The key algorithm used to create the certificate.",
					},
					"serial_number": {
						Type:     types.StringType,
						Computed: true,
						MarkdownDescription: "Number that uniquely identifies the certificate with the CA's system. " +
							"The `format` function can be used to convert this _base 10_ number " +
							"into other bases, such as hex.",
					},
					"is_ca": {
						Type:                types.BoolType,
						Computed:            true,
						MarkdownDescription: "`true` if the certificate is of a CA (Certificate Authority).",
					},
					"version": {
						Type:                types.Int64Type,
						Computed:            true,
						MarkdownDescription: "The version the certificate is in.",
					},
					"issuer": {
						Type:     types.StringType,
						Computed: true,
						MarkdownDescription: "Who verified and signed the certificate, roughly following " +
							"[RFC2253](https://tools.ietf.org/html/rfc2253).",
					},
					"subject": {
						Type:     types.StringType,
						Computed: true,
						MarkdownDescription: "The entity the certificate belongs to, roughly following " +
							"[RFC2253](https://tools.ietf.org/html/rfc2253).",
					},
					"not_before": {
						Type:     types.StringType,
						Computed: true,
						MarkdownDescription: "The time after which the certificate is valid, as an " +
							"[RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
					},
					"not_after": {
						Type:     types.StringType,
						Computed: true,
						MarkdownDescription: "The time until which the certificate is invalid, as an " +
							"[RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.",
					},
					"sha1_fingerprint": {
						Type:                types.StringType,
						Computed:            true,
						MarkdownDescription: "The SHA1 fingerprint of the public key of the certificate.",
					},
					"cert_pem": {
						Type:     types.StringType,
						Computed: true,
						MarkdownDescription: "Certificate data in [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421) format. " +
							"**NOTE**: the [underlying](https://pkg.go.dev/encoding/pem#Encode) " +
							"[libraries](https://pkg.go.dev/golang.org/x/crypto/ssh#MarshalAuthorizedKey) that generate this " +
							"value append a `\\n` at the end of the PEM. " +
							"In case this disrupts your use case, we recommend using " +
							"[`trimspace()`](https://www.terraform.io/language/functions/trimspace).",
					},
				}),
				MarkdownDescription: "The certificates protecting the site, with the root of the chain first.",
			},
			"id": {
				Type:                types.StringType,
				Computed:            true,
				MarkdownDescription: "Unique identifier of this data source: hashing of the certificates in the chain.",
			},
		},
		MarkdownDescription: "Get information about the TLS certificates securing a host.\n\n" +
			"Use this data source to get information, such as SHA1 fingerprint or serial number, " +
			"about the TLS certificates that protects a URL.",
	}, nil
}

func (dst *certificateDataSourceType) NewDataSource(_ context.Context, p tfsdk.Provider) (tfsdk.DataSource, diag.Diagnostics) {
	provider, diagnostics := toProvider(p)
	return &certificateDataSource{provider}, diagnostics
}

func (ds *certificateDataSource) Read(ctx context.Context, req tfsdk.ReadDataSourceRequest, res *tfsdk.ReadDataSourceResponse) {
	var newState certificateDataSourceModel
	req.Config.Get(ctx, &newState)

	var certs []CertificateModel
	if !newState.Content.IsNull() && !newState.Content.IsUnknown() {
		block, _ := pem.Decode([]byte(newState.Content.Value))
		if block == nil {
			res.Diagnostics.AddAttributeError(
				tftypes.NewAttributePath().WithAttributeName("content"),
				"Failed to decoded PEM",
				"Value is not a valid PEM encoding of a certificate",
			)
			return
		}

		preamble, err := pemBlockToPEMPreamble(block)
		if err != nil {
			res.Diagnostics.AddError("Failed to identify PEM preamble", err.Error())
			return
		}

		if preamble != PreambleCertificate {
			res.Diagnostics.AddError(
				"Unexpected PEM preamble",
				fmt.Sprintf("Certificate PEM should be %q, got %q", PreambleCertificate, preamble),
			)
			return
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			res.Diagnostics.AddError("Unable to parse certificate", err.Error())
			return
		}

		certs = []CertificateModel{certificateToStruct(cert)}
	} else {
		targetURL, err := url.Parse(newState.URL.Value)
		if err != nil {
			res.Diagnostics.AddAttributeError(
				tftypes.NewAttributePath().WithAttributeName("url"),
				"Failed to parse URL",
				err.Error(),
			)
			return
		}

		// Determine if we should verify the chain of certificates, or skip said verification
		shouldVerifyChain := newState.VerifyChain.Value

		// Ensure a port is set on the URL, or return an error
		var peerCerts []*x509.Certificate
		switch targetURL.Scheme {
		case HTTPSScheme.String():
			if targetURL.Port() == "" {
				targetURL.Host += ":443"
			}

			// TODO remove this branch and default to use `fetchPeerCertificatesViaHTTPS`
			//   as part of https://github.com/hashicorp/terraform-provider-tls/issues/183
			if ds.provider.isProxyConfigured() {
				peerCerts, err = fetchPeerCertificatesViaHTTPS(targetURL, shouldVerifyChain, ds.provider)
			} else {
				peerCerts, err = fetchPeerCertificatesViaTLS(targetURL, shouldVerifyChain)
			}
		case TLSScheme.String():
			if targetURL.Port() == "" {
				res.Diagnostics.AddError("URL malformed", fmt.Sprintf("Port missing from URL: %s", targetURL.String()))
				return
			}

			peerCerts, err = fetchPeerCertificatesViaTLS(targetURL, shouldVerifyChain)
		default:
			// NOTE: This should never happen, given we validate this at the schema level
			res.Diagnostics.AddError("Unsupported scheme", fmt.Sprintf("Scheme %q not supported", targetURL.String()))
			return
		}
		if err != nil {
			res.Diagnostics.AddError("Failed to identify fetch peer certificates", err.Error())
			return
		}

		// Convert peer certificates to a simple map
		certs = make([]CertificateModel, len(peerCerts))
		for i, peerCert := range peerCerts {
			certs[len(peerCerts)-i-1] = certificateToStruct(peerCert)
		}
	}

	// Set certificates on the state model
	res.Diagnostics.Append(tfsdk.ValueFrom(ctx, certs, types.ListType{
		ElemType: types.ObjectType{
			AttrTypes: x509CertObjectAttrTypes(),
		},
	}, &newState.Certificates)...)
	if res.Diagnostics.HasError() {
		return
	}

	// Set ID as hashing of the certificates
	newState.ID = types.String{Value: hashForState(fmt.Sprintf("%v", certs))}

	// Finally, set the state
	res.Diagnostics.Append(res.State.Set(ctx, newState)...)
}

func fetchPeerCertificatesViaTLS(targetURL *url.URL, shouldVerifyChain bool) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", targetURL.Host, &tls.Config{
		InsecureSkipVerify: !shouldVerifyChain,
	})
	if err != nil {
		return nil, fmt.Errorf("unable to execute TLS connection towards %s: %w", targetURL.Host, err)
	}
	defer conn.Close()

	return conn.ConnectionState().PeerCertificates, nil
}

func fetchPeerCertificatesViaHTTPS(targetURL *url.URL, shouldVerifyChain bool, p *provider) ([]*x509.Certificate, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: !shouldVerifyChain,
			},
			Proxy: p.proxyForRequestFunc(),
		},
	}

	// First attempting an HTTP HEAD: if it fails, ignore errors and move on
	resp, err := client.Head(targetURL.String())
	if err == nil && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		defer resp.Body.Close()
		return resp.TLS.PeerCertificates, nil
	}

	// Then attempting HTTP GET: if this fails we will than report the error
	resp, err = client.Get(targetURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch certificates from URL '%s': %w", targetURL.Scheme, err)
	}
	defer resp.Body.Close()
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		return resp.TLS.PeerCertificates, nil
	}

	return nil, fmt.Errorf("got back response (status: %s) with no certificates from URL '%s': %w", resp.Status, targetURL.Scheme, err)
}

func certificateToStruct(cert *x509.Certificate) CertificateModel {
	certPem := string(pem.EncodeToMemory(&pem.Block{Type: PreambleCertificate.String(), Bytes: cert.Raw}))

	return CertificateModel{
		SignatureAlgorithm: types.String{Value: cert.SignatureAlgorithm.String()},
		PublicKeyAlgorithm: types.String{Value: cert.PublicKeyAlgorithm.String()},
		SerialNumber:       types.String{Value: cert.SerialNumber.String()},
		IsCA:               types.Bool{Value: cert.IsCA},
		Version:            types.Int64{Value: int64(cert.Version)},
		Issuer:             types.String{Value: cert.Issuer.String()},
		Subject:            types.String{Value: cert.Subject.String()},
		NotBefore:          types.String{Value: cert.NotBefore.Format(time.RFC3339)},
		NotAfter:           types.String{Value: cert.NotAfter.Format(time.RFC3339)},
		SHA1Fingerprint:    types.String{Value: fmt.Sprintf("%x", sha1.Sum(cert.Raw))},
		CertPEM:            types.String{Value: certPem},
	}
}

func x509CertObjectAttrTypes() map[string]attr.Type {
	return map[string]attr.Type{
		"signature_algorithm":  types.StringType,
		"public_key_algorithm": types.StringType,
		"serial_number":        types.StringType,
		"is_ca":                types.BoolType,
		"version":              types.Int64Type,
		"issuer":               types.StringType,
		"subject":              types.StringType,
		"not_before":           types.StringType,
		"not_after":            types.StringType,
		"sha1_fingerprint":     types.StringType,
		"cert_pem":             types.StringType,
	}
}
