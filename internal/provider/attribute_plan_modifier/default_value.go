package attribute_plan_modifier

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// defaultValueAttributePlanModifier specifies a default value (attr.Value) for an attribute.
type defaultValueAttributePlanModifier struct {
	DefaultValue attr.Value
}

// DefaultValue is an helper to instantiate a defaultValueAttributePlanModifier.
func DefaultValue(v attr.Value) tfsdk.AttributePlanModifier {
	return &defaultValueAttributePlanModifier{v}
}

var _ tfsdk.AttributePlanModifier = (*defaultValueAttributePlanModifier)(nil)

func (apm *defaultValueAttributePlanModifier) Description(ctx context.Context) string {
	return apm.MarkdownDescription(ctx)
}

func (apm *defaultValueAttributePlanModifier) MarkdownDescription(ctx context.Context) string {
	return fmt.Sprintf("Sets the default value %q (%s) if the attribute is not set", apm.DefaultValue, apm.DefaultValue.Type(ctx))
}

func (apm *defaultValueAttributePlanModifier) Modify(_ context.Context, req tfsdk.ModifyAttributePlanRequest, res *tfsdk.ModifyAttributePlanResponse) {
	// If the attribute configuration is not null, we are done here
	if !req.AttributeConfig.IsNull() {
		return
	}

	// If the attribute plan is "known" and "not null", then a previous plan modifier in the sequence
	// has already been applied, and we don't want to interfere.
	if !req.AttributePlan.IsUnknown() && !req.AttributePlan.IsNull() {
		return
	}

	res.AttributePlan = apm.DefaultValue
}

// readyForRenewalAttributePlanModifier determines whether the certificate is ready for renewal.
type readyForRenewalAttributePlanModifier struct {
}

// ReadyForRenewal is an helper to instantiate a defaultValueAttributePlanModifier.
func ReadyForRenewal() tfsdk.AttributePlanModifier {
	return &readyForRenewalAttributePlanModifier{}
}

var _ tfsdk.AttributePlanModifier = (*readyForRenewalAttributePlanModifier)(nil)

func (apm *readyForRenewalAttributePlanModifier) Description(ctx context.Context) string {
	return apm.MarkdownDescription(ctx)
}

func (apm *readyForRenewalAttributePlanModifier) MarkdownDescription(ctx context.Context) string {
	return "Sets the value of ready_for_renewal depending on value of validity_period_hours and early_renewal_hours"
}

func (apm *readyForRenewalAttributePlanModifier) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, res *tfsdk.ModifyAttributePlanResponse) {
	var validityPeriodHours types.Int64

	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("validity_period_hours"), &validityPeriodHours)...)
	if res.Diagnostics.HasError() {
		return
	}

	if validityPeriodHours.Value == 0 {
		res.AttributePlan = types.Bool{
			Value: true,
		}

		return
	}

	var earlyRenewalHours types.Int64

	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("early_renewal_hours"), &earlyRenewalHours)...)
	if res.Diagnostics.HasError() {
		return
	}

	if earlyRenewalHours.IsNull() || earlyRenewalHours.IsUnknown() {
		return
	}

	if earlyRenewalHours.Value >= validityPeriodHours.Value {
		res.AttributePlan = types.Bool{
			Value: true,
		}

		return
	}
}
