package provider

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func New() *schema.Provider {
	return &schema.Provider{
		ResourcesMap: map[string]*schema.Resource{
			"tls_private_key":         resourcePrivateKey(),
			"tls_locally_signed_cert": resourceLocallySignedCert(),
			"tls_self_signed_cert":    resourceSelfSignedCert(),
			"tls_cert_request":        resourceCertRequest(),
		},
		DataSourcesMap: map[string]*schema.Resource{
			"tls_public_key":  dataSourcePublicKey(),
			"tls_certificate": dataSourceCertificate(),
		},
		Schema: map[string]*schema.Schema{
			"proxy": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"url": {
							Type:             schema.TypeString,
							Optional:         true,
							ValidateDiagFunc: validation.ToDiagFunc(validation.IsURLWithScheme(SupportedProxySchemesStr())),
							ConflictsWith:    []string{"proxy.0.from_env"},
							Description: "URL used to connect to the Proxy. " +
								fmt.Sprintf("Accepted schemes are: `%s`. ", strings.Join(SupportedProxySchemesStr(), "`, `")),
						},
						"username": {
							Type:         schema.TypeString,
							Optional:     true,
							RequiredWith: []string{"proxy.0.url"},
							Description:  "Username (or Token) used for Basic authentication against the Proxy.",
						},
						"password": {
							Type:         schema.TypeString,
							Optional:     true,
							Sensitive:    true,
							RequiredWith: []string{"proxy.0.username"},
							Description:  "Password used for Basic authentication against the Proxy.",
						},
						"from_env": {
							Type:          schema.TypeBool,
							Optional:      true,
							Default:       false,
							ConflictsWith: []string{"proxy.0.url", "proxy.0.username", "proxy.0.password"},
							Description: "When `true` the provider will discover the proxy configuration from environment variables. " +
								"This is based upon [`http.ProxyFromEnvironment`](https://pkg.go.dev/net/http#ProxyFromEnvironment) " +
								"and it supports the same environment variables (default: `true`).",
						},
					},
				},
				Description: "Proxy used by resources and data sources that connect to external endpoints.",
			},
		},
		ConfigureContextFunc: configureProvider,
	}
}

type providerConfig struct {
	proxyURL     *url.URL
	proxyFromEnv bool
}

func configureProvider(_ context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
	var diags diag.Diagnostics
	var config = &providerConfig{}
	var err error

	if proxyUrl, ok := data.GetOk("proxy.0.url"); ok {
		config.proxyURL, err = url.Parse(proxyUrl.(string))
		if err != nil {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Error,
				Summary:  fmt.Sprintf("Unable to parse proxy URL '%s': %v", proxyUrl, err),
			})
		}
	}

	if proxyUsername, ok := data.GetOk("proxy.0.username"); ok {
		// NOTE: we know that `.proxyURL` is set, as this is imposed by the provider schema
		config.proxyURL.User = url.User(proxyUsername.(string))
	}

	if proxyPassword, ok := data.GetOk("proxy.0.password"); ok {
		// NOTE: we know that `.proxyURL.User.Username()` is set, as this is imposed by the provider schema
		config.proxyURL.User = url.UserPassword(config.proxyURL.User.Username(), proxyPassword.(string))
	}

	if proxyFromEnv, ok := data.GetOk("proxy.0.from_env"); ok {
		config.proxyFromEnv = proxyFromEnv.(bool)
	}

	return config, diags
}

// proxyForRequestFunc is an adapter that returns the configured proxy.
//
// It works by returning a function that, given an *http.Request,
// provides the http.Client with the *url.URL to the proxy.
func (pc *providerConfig) proxyForRequestFunc() func(_ *http.Request) (*url.URL, error) {
	if pc.proxyFromEnv {
		return http.ProxyFromEnvironment
	}

	return func(_ *http.Request) (*url.URL, error) {
		return pc.proxyURL, nil
	}
}
