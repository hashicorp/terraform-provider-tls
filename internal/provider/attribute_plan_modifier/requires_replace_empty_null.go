package attribute_plan_modifier

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func RequiresReplaceNullEmpty() tfsdk.AttributePlanModifier {
	return requiresReplaceNullEmpty{}
}

type requiresReplaceNullEmpty struct{}

func (r requiresReplaceNullEmpty) Modify(ctx context.Context, req tfsdk.ModifyAttributePlanRequest, resp *tfsdk.ModifyAttributePlanResponse) {
	if req.AttributeConfig == nil || req.AttributePlan == nil || req.AttributeState == nil {
		// shouldn't happen, but let's not panic if it does
		return
	}

	if req.AttributePlan.IsUnknown() {

		emptyStateString := types.String{}

		if req.AttributeState.Equal(emptyStateString) {
			resp.AttributePlan = emptyStateString
			return
		}

		nullStateString := types.String{
			Null: true,
		}

		if req.AttributeState.Equal(nullStateString) {
			resp.AttributePlan = nullStateString
			return
		}

		emptyStateList := types.List{
			ElemType: types.StringType,
			Elems:    []attr.Value{},
		}

		if req.AttributeState.Equal(emptyStateList) {
			resp.AttributePlan = emptyStateList
			return
		}

		nullStateList := types.List{
			Null:     true,
			ElemType: types.StringType,
		}

		if req.AttributeState.Equal(nullStateList) {
			resp.AttributePlan = nullStateList
			return
		}
	}

	if req.AttributePlan.Equal(req.AttributeState) {
		// if the plan and the state are in agreement, this attribute
		// isn't changing, don't require replace
		return
	}

	resp.RequiresReplace = true
}

func (r requiresReplaceNullEmpty) Description(ctx context.Context) string {
	return "If the value of this attribute changes, Terraform will destroy and recreate the resource."
}

func (r requiresReplaceNullEmpty) MarkdownDescription(ctx context.Context) string {
	return "If the value of this attribute changes, Terraform will destroy and recreate the resource."
}
