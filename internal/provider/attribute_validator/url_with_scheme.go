package attribute_validator

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

// urlWithSchemeAttributeValidator checks that a types.String attribute
// is indeed a URL and its scheme is one of the given `acceptableSchemes`.
//
// Instances should be created via UrlWithScheme function.
type urlWithSchemeAttributeValidator struct {
	acceptableSchemes []string
}

// UrlWithScheme is a helper to instantiate a urlWithSchemeAttributeValidator.
func UrlWithScheme(acceptableSchemes ...string) tfsdk.AttributeValidator {
	return &urlWithSchemeAttributeValidator{acceptableSchemes}
}

var _ tfsdk.AttributeValidator = (*urlWithSchemeAttributeValidator)(nil)

func (av *urlWithSchemeAttributeValidator) Description(ctx context.Context) string {
	return av.MarkdownDescription(ctx)
}

func (av *urlWithSchemeAttributeValidator) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("Ensures that the attribute is a URL and its scheme is one of: %q", av.acceptableSchemes)
}

func (av *urlWithSchemeAttributeValidator) Validate(ctx context.Context, req tfsdk.ValidateAttributeRequest, res *tfsdk.ValidateAttributeResponse) {
	if req.AttributeConfig.IsNull() || req.AttributeConfig.IsUnknown() {
		return
	}

	tflog.Debug(ctx, "Validating attribute value is a URL with acceptable scheme", map[string]interface{}{
		"attribute":         req.AttributePath.String(),
		"acceptableSchemes": strings.Join(av.acceptableSchemes, ","),
	})

	var v types.String
	diags := tfsdk.ValueAs(ctx, req.AttributeConfig, &v)
	if diags.HasError() {
		res.Diagnostics.Append(diags...)
		return
	}

	if v.IsNull() || v.IsUnknown() {
		return
	}

	u, err := url.Parse(v.Value)
	if err != nil {
		res.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Invalid URL",
			fmt.Sprintf("Parsing URL %q failed: %v", v.Value, err),
		)
		return
	}

	if u.Host == "" {
		res.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Invalid URL",
			fmt.Sprintf("URL %q contains no host", u.String()),
		)
		return
	}

	for _, s := range av.acceptableSchemes {
		if u.Scheme == s {
			return
		}
	}

	res.Diagnostics.AddAttributeError(
		req.AttributePath,
		"Invalid URL scheme",
		fmt.Sprintf("URL %q expected to use scheme from %q, got: %q", u.String(), av.acceptableSchemes, u.Scheme),
	)
}
