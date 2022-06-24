package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/attribute_validation"
)

type provider struct {
	proxyURL     *url.URL
	proxyFromEnv bool
}

// Enforce interfaces we want provider to implement.
var _ tfsdk.Provider = (*provider)(nil)

func New() tfsdk.Provider {
	return &provider{
		proxyURL:     nil,
		proxyFromEnv: false, //< TODO switch default to `true` as part of https://github.com/hashicorp/terraform-provider-tls/issues/183
	}
}

func (p *provider) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Attributes: map[string]tfsdk.Attribute{
			"proxy": {
				Optional: true,
				Attributes: tfsdk.SingleNestedAttributes(map[string]tfsdk.Attribute{
					"url": {
						Type:     types.StringType,
						Optional: true,
						Validators: []tfsdk.AttributeValidator{
							attribute_validation.UrlWithScheme(supportedProxySchemesStr()...),
							attribute_validation.ConflictsWith(tftypes.NewAttributePath().WithAttributeName("proxy").WithAttributeName("from_env")),
						},
						MarkdownDescription: "URL used to connect to the Proxy. " +
							fmt.Sprintf("Accepted schemes are: `%s`. ", strings.Join(supportedProxySchemesStr(), "`, `")),
					},
					"username": {
						Type:     types.StringType,
						Optional: true,
						Validators: []tfsdk.AttributeValidator{
							attribute_validation.RequiredWith(tftypes.NewAttributePath().WithAttributeName("proxy").WithAttributeName("url")),
						},
						MarkdownDescription: "Username (or Token) used for Basic authentication against the Proxy.",
					},
					"password": {
						Type:      types.StringType,
						Optional:  true,
						Sensitive: true,
						Validators: []tfsdk.AttributeValidator{
							attribute_validation.RequiredWith(tftypes.NewAttributePath().WithAttributeName("proxy").WithAttributeName("username")),
						},
						MarkdownDescription: "Password used for Basic authentication against the Proxy.",
					},
					"from_env": {
						Type:     types.BoolType,
						Optional: true,
						Computed: true,
						Validators: []tfsdk.AttributeValidator{
							attribute_validation.ConflictsWith(
								tftypes.NewAttributePath().WithAttributeName("proxy").WithAttributeName("url"),
								tftypes.NewAttributePath().WithAttributeName("proxy").WithAttributeName("username"),
								tftypes.NewAttributePath().WithAttributeName("proxy").WithAttributeName("password"),
							),
						},
						MarkdownDescription: "When `true` the provider will discover the proxy configuration from environment variables. " +
							"This is based upon [`http.ProxyFromEnvironment`](https://pkg.go.dev/net/http#ProxyFromEnvironment) " +
							"and it supports the same environment variables (default: `false`). " +
							"**NOTE**: the default value for this argument will be change to `true` in the next major release.",
					},
				}),
				MarkdownDescription: "Proxy used by resources and data sources that connect to external endpoints.",
			},
		},
	}, nil
}

func (p *provider) Configure(ctx context.Context, req tfsdk.ConfigureProviderRequest, res *tfsdk.ConfigureProviderResponse) {
	tflog.Debug(ctx, "Configuring provider")

	var err error

	// Load configuration into the model
	var conf providerConfigModel
	res.Diagnostics.Append(req.Config.Get(ctx, &conf)...)
	if res.Diagnostics.HasError() {
		return
	}
	if conf.Proxy.IsNull() || conf.Proxy.IsUnknown() {
		tflog.Debug(ctx, "No proxy configuration detected", map[string]interface{}{
			"conf": fmt.Sprintf("%+v", conf),
		})
		return
	}

	// Load proxy configuration into model
	var proxyConf providerProxyConfigModel
	res.Diagnostics.Append(conf.Proxy.As(ctx, &proxyConf, types.ObjectAsOptions{})...)
	if res.Diagnostics.HasError() {
		return
	}
	tflog.Debug(ctx, "Loaded provider configuration", map[string]interface{}{
		"conf":      fmt.Sprintf("%+v", conf),
		"proxyConf": fmt.Sprintf("%+v", proxyConf),
	})

	// Parse the URL
	if !proxyConf.URL.IsNull() && !proxyConf.URL.IsUnknown() {
		tflog.Debug(ctx, "Configuring Proxy via URL", map[string]interface{}{
			"url": proxyConf.URL.Value,
		})

		p.proxyURL, err = url.Parse(proxyConf.URL.Value)
		if err != nil {
			res.Diagnostics.AddError(fmt.Sprintf("Unable to parse proxy URL %q", proxyConf.URL.Value), err.Error())
		}
	}

	if !proxyConf.Username.IsNull() && !proxyConf.Username.IsUnknown() {
		tflog.Debug(ctx, "Adding username to Proxy URL configuration", map[string]interface{}{
			"username": proxyConf.Username.Value,
		})

		// NOTE: we know that `.proxyURL` is set, as this is imposed by the provider schema
		p.proxyURL.User = url.User(proxyConf.Username.Value)
	}

	if !proxyConf.Password.IsNull() && !proxyConf.Password.IsUnknown() {
		tflog.Debug(ctx, "Adding password to Proxy URL configuration")

		// NOTE: we know that `.proxyURL.User.Username()` is set, as this is imposed by the provider schema
		p.proxyURL.User = url.UserPassword(p.proxyURL.User.Username(), proxyConf.Password.Value)
	}

	if !proxyConf.FromEnv.IsNull() && !proxyConf.FromEnv.IsUnknown() {
		tflog.Debug(ctx, "Configuring Proxy via Environment Variables")

		p.proxyFromEnv = proxyConf.FromEnv.Value
	}
}

func (p *provider) GetResources(_ context.Context) (map[string]tfsdk.ResourceType, diag.Diagnostics) {
	return map[string]tfsdk.ResourceType{
		"tls_private_key":         &privateKeyResourceType{},
		"tls_cert_request":        &certRequestResourceType{},
		"tls_self_signed_cert":    &selfSignedCertResourceType{},
		"tls_locally_signed_cert": &locallySignedCertResourceType{},
	}, nil
}

func (p *provider) GetDataSources(_ context.Context) (map[string]tfsdk.DataSourceType, diag.Diagnostics) {
	return map[string]tfsdk.DataSourceType{
		"tls_public_key":  &publicKeyDataSourceType{},
		"tls_certificate": &certificateDataSourceType{},
	}, nil
}

// proxyForRequestFunc is an adapter that returns the configured proxy.
//
// It works by returning a function that, given an *http.Request,
// provides the http.Client with the *url.URL to the proxy.
func (p *provider) proxyForRequestFunc() func(_ *http.Request) (*url.URL, error) {
	if p.proxyURL != nil {
		return func(_ *http.Request) (*url.URL, error) {
			return p.proxyURL, nil
		}
	}

	if p.proxyFromEnv {
		return http.ProxyFromEnvironment
	}

	return func(_ *http.Request) (*url.URL, error) {
		return p.proxyURL, fmt.Errorf("proxy not configured")
	}
}

// isProxyConfigured returns true if a proxy configuration was detected as part of provider.Configure.
func (p *provider) isProxyConfigured() bool {
	return p.proxyURL != nil || p.proxyFromEnv
}

// toProvider can be used to cast a generic tfsdk.Provider reference to this specific provider.
// This is ideally used in DataSourceType.NewDataSource and ResourceType.NewResource calls.
func toProvider(in tfsdk.Provider) (*provider, diag.Diagnostics) {
	var diags diag.Diagnostics

	p, ok := in.(*provider)

	if !ok {
		diags.AddError(
			"Unexpected Provider Instance Type",
			fmt.Sprintf("While creating the data source or resource, an unexpected provider type (%T) was received. "+
				"This is always a bug in the provider code and should be reported to the provider developers.", p,
			),
		)
		return nil, diags
	}

	if p == nil {
		diags.AddError(
			"Unexpected Provider Instance Type",
			"While creating the data source or resource, an unexpected empty (null) provider instance was received. "+
				"This is always a bug in the provider code and should be reported to the provider developers.",
		)
		return nil, diags
	}

	return p, diags
}
