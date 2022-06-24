package attribute_validation

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
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
		"attribute":         attrPathToString(req.AttributePath),
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

// oneOfAttributeValidator checks that values held in the attribute
// are one of the given `acceptableValues`.
//
// This validator can be used with all primitive `types.*`, as well as
// collections (`types.List`, `types.Set`, `types.Map` and `types.Object`):
// for key/value collections, the validator will compare the values.
//
// Instances should be created via OneOf function.
type oneOfAttributeValidator struct {
	acceptableValues []attr.Value
}

// OneOf is a helper to instantiate a oneOfAttributeValidator.
func OneOf(acceptableValues ...attr.Value) tfsdk.AttributeValidator {
	return &oneOfAttributeValidator{acceptableValues}
}

var _ tfsdk.AttributeValidator = (*oneOfAttributeValidator)(nil)

func (av *oneOfAttributeValidator) Description(ctx context.Context) string {
	return av.MarkdownDescription(ctx)
}

func (av *oneOfAttributeValidator) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("Ensures that the attribute is one of: %q", av.acceptableValues)
}

func (av *oneOfAttributeValidator) Validate(_ context.Context, req tfsdk.ValidateAttributeRequest, res *tfsdk.ValidateAttributeResponse) {
	if req.AttributeConfig.IsNull() || req.AttributeConfig.IsUnknown() {
		return
	}

	var values []attr.Value

	switch typedAttributeConfig := req.AttributeConfig.(type) {
	case types.List:
		values = typedAttributeConfig.Elems
	case types.Map:
		values = make([]attr.Value, 0, len(typedAttributeConfig.Elems))
		for _, v := range typedAttributeConfig.Elems {
			values = append(values, v)
		}
	case types.Set:
		values = typedAttributeConfig.Elems
	case types.Object:
		values = make([]attr.Value, 0, len(typedAttributeConfig.Attrs))
		for _, v := range typedAttributeConfig.Attrs {
			values = append(values, v)
		}
	default:
		values = []attr.Value{typedAttributeConfig}
	}

	for _, v := range values {
		if !av.isValid(v) {
			res.Diagnostics.AddAttributeError(
				req.AttributePath,
				"Invalid Attribute",
				fmt.Sprintf("Value %q must be one of %q", v, av.acceptableValues),
			)
		}
	}
}

func (av *oneOfAttributeValidator) isValid(v attr.Value) bool {
	for _, acceptableV := range av.acceptableValues {
		if v.Equal(acceptableV) {
			return true
		}
	}

	return false
}

// requiredWithAttributeValidator checks that a set of *tftypes.AttributePath,
// including the attribute it's applied to, are set simultaneously.
// This implements the validation logic declaratively within the tfsdk.Schema.
//
// The provided tftypes.AttributePath must be "absolute",
// and starting with top level attribute names.
type requiredWithAttributeValidator struct {
	attrPaths []*tftypes.AttributePath
}

// RequiredWith is a helper to instantiate requiredWithAttributeValidator.
func RequiredWith(attributePaths ...*tftypes.AttributePath) tfsdk.AttributeValidator {
	return &requiredWithAttributeValidator{attributePaths}
}

var _ tfsdk.AttributeValidator = (*requiredWithAttributeValidator)(nil)

func (av requiredWithAttributeValidator) Description(ctx context.Context) string {
	return av.MarkdownDescription(ctx)
}

func (av requiredWithAttributeValidator) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("Ensure that if an attribute is set, also these are set: %q", av.attrPaths)
}

func (av requiredWithAttributeValidator) Validate(ctx context.Context, req tfsdk.ValidateAttributeRequest, res *tfsdk.ValidateAttributeResponse) {
	tflog.Debug(ctx, "Validating attribute is set together with other required attributes", map[string]interface{}{
		"attribute":          attrPathToString(req.AttributePath),
		"requiredAttributes": av.attrPaths,
	})

	var v attr.Value
	res.Diagnostics.Append(tfsdk.ValueAs(ctx, req.AttributeConfig, &v)...)
	if res.Diagnostics.HasError() {
		return
	}

	for _, path := range av.attrPaths {
		var o attr.Value
		res.Diagnostics.Append(req.Config.GetAttribute(ctx, path, &o)...)
		if res.Diagnostics.HasError() {
			return
		}

		if !v.IsNull() && o.IsNull() {
			res.Diagnostics.AddAttributeError(
				req.AttributePath,
				fmt.Sprintf("Attribute %q missing", attrPathToString(path)),
				fmt.Sprintf("%q must be specified when %q is specified", attrPathToString(path), attrPathToString(req.AttributePath)),
			)
			return
		}
	}
}

// conflictsWithAttributeValidator checks that a set of *tftypes.AttributePath,
// including the attribute it's applied to, are not set simultaneously.
// This implements the validation logic declaratively within the tfsdk.Schema.
//
// The provided tftypes.AttributePath must be "absolute",
// and starting with top level attribute names.
type conflictsWithAttributeValidator struct {
	attrPaths []*tftypes.AttributePath
}

// ConflictsWith is a helper to instantiate conflictsWithAttributeValidator.
func ConflictsWith(attributePaths ...*tftypes.AttributePath) tfsdk.AttributeValidator {
	return &conflictsWithAttributeValidator{attributePaths}
}

var _ tfsdk.AttributeValidator = (*conflictsWithAttributeValidator)(nil)

func (av conflictsWithAttributeValidator) Description(ctx context.Context) string {
	return av.MarkdownDescription(ctx)
}

func (av conflictsWithAttributeValidator) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("Ensure that if an attribute is set, these are not set: %q", av.attrPaths)
}

func (av conflictsWithAttributeValidator) Validate(ctx context.Context, req tfsdk.ValidateAttributeRequest, res *tfsdk.ValidateAttributeResponse) {
	tflog.Debug(ctx, "Validating attribute is not set together with other conflicting attributes", map[string]interface{}{
		"attribute":             attrPathToString(req.AttributePath),
		"conflictingAttributes": av.attrPaths,
	})

	var v attr.Value
	res.Diagnostics.Append(tfsdk.ValueAs(ctx, req.AttributeConfig, &v)...)
	if res.Diagnostics.HasError() {
		return
	}

	for _, path := range av.attrPaths {
		var o attr.Value
		res.Diagnostics.Append(req.Config.GetAttribute(ctx, path, &o)...)
		if res.Diagnostics.HasError() {
			return
		}

		if !v.IsNull() && !o.IsNull() {
			res.Diagnostics.AddAttributeError(
				req.AttributePath,
				fmt.Sprintf("Attribute %q conflicting", attrPathToString(path)),
				fmt.Sprintf("%q cannot be specified when %q is specified", attrPathToString(path), attrPathToString(req.AttributePath)),
			)
			return
		}
	}
}

// exactlyOneOfAttributeValidator checks that of a set of *tftypes.AttributePath,
// including the attribute it's applied to, one and only one attribute out of all specified is configured.
// It will also cause a validation error if none are specified.
//
// The provided tftypes.AttributePath must be "absolute",
// and starting with top level attribute names.
type exactlyOneOfAttributeValidator struct {
	attrPaths []*tftypes.AttributePath
}

// ExactlyOneOf is a helper to instantiate exactlyOneOfAttributeValidator.
func ExactlyOneOf(attributePaths ...*tftypes.AttributePath) tfsdk.AttributeValidator {
	return &exactlyOneOfAttributeValidator{attributePaths}
}

var _ tfsdk.AttributeValidator = (*exactlyOneOfAttributeValidator)(nil)

func (av exactlyOneOfAttributeValidator) Description(ctx context.Context) string {
	return av.MarkdownDescription(ctx)
}

func (av exactlyOneOfAttributeValidator) MarkdownDescription(_ context.Context) string {
	return fmt.Sprintf("Ensure that one and only one attribute from this collection is set: %q", av.attrPaths)
}

func (av exactlyOneOfAttributeValidator) Validate(ctx context.Context, req tfsdk.ValidateAttributeRequest, res *tfsdk.ValidateAttributeResponse) {
	// Assemble a slice of paths, ensuring we don't repeat the attribute this validator is applied to
	var paths []*tftypes.AttributePath
	if containsAttrPath(req.AttributePath, av.attrPaths...) {
		paths = av.attrPaths
	} else {
		paths = append(av.attrPaths, req.AttributePath)
	}

	tflog.Debug(ctx, "Validating that one and only one attribute is set", map[string]interface{}{
		"exactlyOneOfAttributes": paths,
	})

	count := 0
	for _, path := range paths {
		var v attr.Value
		req.Config.GetAttribute(ctx, path, &v)

		if !v.IsNull() {
			count++
		}
	}

	if count == 0 {
		res.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Invalid combination of arguments: no attribute set, when one and only one was expected",
			fmt.Sprintf("No attribute out of %q has been set", joinAttrPathsToString(paths...)),
		)
	}

	if count > 1 {
		res.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Invalid combination of arguments: more than one attribute set, when only one was expected",
			fmt.Sprintf("More than one attribute out of %q has been set", joinAttrPathsToString(paths...)),
		)
	}
}

// atLeastOneOfAttributeValidator checks that of a set of *tftypes.AttributePath,
//// including the attribute it's applied to, at least one attribute out of all specified is configured.
////
//// The provided tftypes.AttributePath must be "absolute",
//// and starting with top level attribute names.
type atLeastOneOfAttributeValidator struct {
	attrPaths []*tftypes.AttributePath
}

// AtLeastOneOf is a helper to instantiate exactlyOneOfAttributeValidator.
func AtLeastOneOf(attributePaths ...*tftypes.AttributePath) tfsdk.AttributeValidator {
	return &atLeastOneOfAttributeValidator{attributePaths}
}

var _ tfsdk.AttributeValidator = (*atLeastOneOfAttributeValidator)(nil)

func (av atLeastOneOfAttributeValidator) Description(ctx context.Context) string {
	return av.MarkdownDescription(ctx)
}

func (av atLeastOneOfAttributeValidator) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf("Ensure that at least one attribute from this collection is set: %q", av.attrPaths)
}

func (av atLeastOneOfAttributeValidator) Validate(ctx context.Context, req tfsdk.ValidateAttributeRequest, res *tfsdk.ValidateAttributeResponse) {
	// Assemble a slice of paths, ensuring we don't repeat the attribute this validator is applied to
	var paths []*tftypes.AttributePath
	if containsAttrPath(req.AttributePath, av.attrPaths...) {
		paths = av.attrPaths
	} else {
		paths = append(av.attrPaths, req.AttributePath)
	}

	tflog.Debug(ctx, "Validating that at least one attribute is set", map[string]interface{}{
		"atLeastOneOfAttributes": paths,
	})

	count := 0
	for _, path := range paths {
		var v attr.Value
		req.Config.GetAttribute(ctx, path, &v)

		if !v.IsNull() {
			count++
		}
	}

	if count == 0 {
		res.Diagnostics.AddAttributeError(
			req.AttributePath,
			"Invalid combination of arguments: no attribute set, when at least one was expected",
			fmt.Sprintf("No attribute out of %q has been set", joinAttrPathsToString(paths...)),
		)
	}
}

// attrPathToString takes all the tftypes.AttributePathStep in a tftypes.AttributePath and concatenates them,
// using `.` as separator.
//
// This should be used only when trying to "print out" a tftypes.AttributePath in a log or an error message.
func attrPathToString(path *tftypes.AttributePath) string {
	var res strings.Builder
	for pos, step := range path.Steps() {
		if pos != 0 {
			res.WriteString(".")
		}
		switch v := step.(type) {
		case tftypes.AttributeName:
			res.WriteString(string(v))
		case tftypes.ElementKeyString:
			res.WriteString(string(v))
		case tftypes.ElementKeyInt:
			res.WriteString(strconv.FormatInt(int64(v), 10))
		case tftypes.ElementKeyValue:
			res.WriteString(tftypes.Value(v).String())
		}
	}

	return res.String()
}

// joinAttrPathsToString works similarly to strings.Join: it takes a collection of *tftypes.AttributePath,
// applies to each attrPathToString, and the resulting strings with a `,` separator.
//
// This should be used only when trying to "print out" a tftypes.AttributePath in a log or an error message.
func joinAttrPathsToString(paths ...*tftypes.AttributePath) string {
	res := make([]string, len(paths))
	for i, path := range paths {
		res[i] = attrPathToString(path)
	}

	return strings.Join(res, ",")
}

// containsAttrPath returns true if needle (one *tftypes.AttributePath) can be found in haystack (collection of *tftypes.AttributePath).
func containsAttrPath(needle *tftypes.AttributePath, haystack ...*tftypes.AttributePath) bool {
	for _, p := range haystack {
		if needle.Equal(p) {
			return true
		}
	}
	return false
}
