package attribute_plan_modifier_bool

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// readyForRenewalAttributePlanModifier determines whether the certificate is ready for renewal.
type readyForRenewalAttributePlanModifier struct {
}

// ReadyForRenewal is an helper to instantiate a defaultValueAttributePlanModifier.
func ReadyForRenewal() planmodifier.Bool {
	return &readyForRenewalAttributePlanModifier{}
}

var _ planmodifier.Bool = (*readyForRenewalAttributePlanModifier)(nil)

func (apm *readyForRenewalAttributePlanModifier) Description(ctx context.Context) string {
	return apm.MarkdownDescription(ctx)
}

func (apm *readyForRenewalAttributePlanModifier) MarkdownDescription(ctx context.Context) string {
	return "Sets the value of ready_for_renewal depending on value of validity_period_hours and early_renewal_hours"
}

func (apm *readyForRenewalAttributePlanModifier) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, res *planmodifier.BoolResponse) {
	var validityPeriodHours types.Int64

	res.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("validity_period_hours"), &validityPeriodHours)...)
	if res.Diagnostics.HasError() {
		return
	}

	if validityPeriodHours.ValueInt64() == 0 {
		res.PlanValue = types.BoolValue(true)

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

	if earlyRenewalHours.ValueInt64() >= validityPeriodHours.ValueInt64() {
		res.PlanValue = types.BoolValue(true)

		return
	}
}
