package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/schemavalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/attribute_validator"
	"golang.org/x/net/http/httpproxy"
)

type tlsProvider struct {
	proxyURL     *url.URL
	proxyFromEnv bool
}

// Enforce interfaces we want provider to implement.
var _ provider.Provider = (*tlsProvider)(nil)
var _ provider.ProviderWithMetadata = (*tlsProvider)(nil)

func New() provider.Provider {
	return &tlsProvider{}
}

func (p *tlsProvider) resetConfig() {
	p.proxyURL = nil
	p.proxyFromEnv = true
}

func (p *tlsProvider) Metadata(_ context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "tls"
}

func (p *tlsProvider) GetSchema(_ context.Context) (tfsdk.Schema, diag.Diagnostics) {
	return tfsdk.Schema{
		Blocks: map[string]tfsdk.Block{
			"proxy": {
				NestingMode: tfsdk.BlockNestingModeList,
				MinItems:    0,
				MaxItems:    1,
				// TODO Remove the validators below, once a fix for https://github.com/hashicorp/terraform-plugin-framework/issues/421 ships
				Validators: []tfsdk.AttributeValidator{
					listvalidator.SizeBetween(0, 1),
				},
				Attributes: map[string]tfsdk.Attribute{
					"url": {
						Type:     types.StringType,
						Optional: true,
						Validators: []tfsdk.AttributeValidator{
							attribute_validator.UrlWithScheme(supportedProxySchemesStr()...),
							schemavalidator.ConflictsWith(path.MatchRelative().AtParent().AtName("from_env")),
						},
						MarkdownDescription: "URL used to connect to the Proxy. " +
							fmt.Sprintf("Accepted schemes are: `%s`. ", strings.Join(supportedProxySchemesStr(), "`, `")),
					},
					"username": {
						Type:     types.StringType,
						Optional: true,
						Validators: []tfsdk.AttributeValidator{
							schemavalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("url")),
						},
						MarkdownDescription: "Username (or Token) used for Basic authentication against the Proxy.",
					},
					"password": {
						Type:      types.StringType,
						Optional:  true,
						Sensitive: true,
						Validators: []tfsdk.AttributeValidator{
							schemavalidator.AlsoRequires(path.MatchRelative().AtParent().AtName("username")),
						},
						MarkdownDescription: "Password used for Basic authentication against the Proxy.",
					},
					"from_env": {
						Type:     types.BoolType,
						Optional: true,
						Computed: true,
						Validators: []tfsdk.AttributeValidator{
							schemavalidator.ConflictsWith(
								path.MatchRelative().AtParent().AtName("url"),
								path.MatchRelative().AtParent().AtName("username"),
								path.MatchRelative().AtParent().AtName("password"),
							),
						},
						MarkdownDescription: "When `true` the provider will discover the proxy configuration from environment variables. " +
							"This is based upon [`http.ProxyFromEnvironment`](https://pkg.go.dev/net/http#ProxyFromEnvironment) " +
							"and it supports the same environment variables (default: `true`).",
					},
				},
				MarkdownDescription: "Proxy used by resources and data sources that connect to external endpoints.",
			},
		},
		MarkdownDescription: "Provider configuration",
	}, nil
}

func (p *tlsProvider) Configure(ctx context.Context, req provider.ConfigureRequest, res *provider.ConfigureResponse) {
	tflog.Debug(ctx, "Configuring provider")
	p.resetConfig()

	// Since the provider instance is being passed, ensure these response
	// values are always set before early returns, etc.
	res.DataSourceData = p
	res.ResourceData = p

	var err error

	// Load configuration into the model
	var conf providerConfigModel
	res.Diagnostics.Append(req.Config.Get(ctx, &conf)...)
	if res.Diagnostics.HasError() {
		return
	}
	if conf.Proxy.IsNull() || conf.Proxy.IsUnknown() || len(conf.Proxy.Elems) == 0 {
		tflog.Debug(ctx, "No proxy configuration detected: using provider defaults")
		return
	}

	// Load proxy configuration into model
	proxyConfSlice := make([]providerProxyConfigModel, 1)
	res.Diagnostics.Append(conf.Proxy.ElementsAs(ctx, &proxyConfSlice, true)...)
	if res.Diagnostics.HasError() {
		return
	}
	if len(proxyConfSlice) != 1 {
		res.Diagnostics.AddAttributeError(
			path.Root("proxy"),
			"Provider Proxy Configuration Handling Error",
			"The provider failed to fully load the expected proxy configuration, even if it appears to be present. "+
				"This is always a bug in the Terraform Provider and should be reported to the provider developers.",
		)
		return
	}
	proxyConf := proxyConfSlice[0]
	tflog.Debug(ctx, "Loaded provider configuration")

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

	tflog.Debug(ctx, "Provider configuration", map[string]interface{}{
		"provider": fmt.Sprintf("%+v", p),
	})
}

func (p *tlsProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewCertRequestResource,
		NewLocallySignedCertResource,
		NewPrivateKeyResource,
		NewSelfSignedCertResource,
	}
}

func (p *tlsProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewCertificateDataSource,
		NewPublicKeyDataSource,
	}
}

// proxyForRequestFunc is an adapter that returns the configured proxy.
//
// It works by returning a function that, given an *http.Request,
// provides the http.Client with the *url.URL to the proxy.
//
// It will return nil if there is no proxy configured.
func (p *tlsProvider) proxyForRequestFunc(ctx context.Context) func(_ *http.Request) (*url.URL, error) {
	if !p.isProxyConfigured() {
		tflog.Debug(ctx, "Proxy not configured")
		return nil
	}

	if p.proxyURL != nil {
		tflog.Debug(ctx, "Proxy via URL")
		return func(_ *http.Request) (*url.URL, error) {
			tflog.Debug(ctx, "Using proxy (URL)", map[string]interface{}{
				"proxy": p.proxyURL,
			})
			return p.proxyURL, nil
		}
	}

	if p.proxyFromEnv {
		tflog.Debug(ctx, "Proxy via ENV")
		return func(req *http.Request) (*url.URL, error) {
			// NOTE: this is based upon `http.ProxyFromEnvironment`,
			// but it avoids a memoization optimization (i.e. fetching environment variables once)
			// that causes issues when testing the provider.
			proxyURL, err := httpproxy.FromEnvironment().ProxyFunc()(req.URL)
			if err != nil {
				return nil, err
			}

			tflog.Debug(ctx, "Using proxy (ENV)", map[string]interface{}{
				"proxy": proxyURL,
			})
			return proxyURL, err
		}
	}

	return nil
}

// isProxyConfigured returns true if a proxy configuration was detected as part of provider.Configure.
func (p *tlsProvider) isProxyConfigured() bool {
	return p.proxyURL != nil || p.proxyFromEnv
}

// toProvider can be used to cast a generic provider.Provider reference to this specific provider.
// This is ideally used in DataSourceType.NewDataSource and ResourceType.NewResource calls.
func toProvider(in any) (*tlsProvider, diag.Diagnostics) {
	if in == nil {
		return nil, nil
	}

	var diags diag.Diagnostics

	p, ok := in.(*tlsProvider)

	if !ok {
		diags.AddError(
			"Unexpected Provider Instance Type",
			fmt.Sprintf("While creating the data source or resource, an unexpected provider type (%T) was received. "+
				"This is always a bug in the provider code and should be reported to the provider developers.", in,
			),
		)
		return nil, diags
	}

	return p, diags
}
