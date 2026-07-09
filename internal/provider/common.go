// Copyright IBM Corp. 2017, 2026
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// resolvePrivateKeyPEM picks the private key PEM an operation should use, given a
// plain (state-backed) attribute value and the config path of its write-only twin.
//
// The choice is driven by the configuration, not by state: a write-only value only
// ever exists in config (it is null in the plan and state), so we read it from
// config and, when set, prefer it. Otherwise we fall back to the plain attribute.
// The resource's config validators guarantee exactly one of the two is set, so this
// never has to resolve an ambiguous "both set" case.
//
// GetAttribute reports problems (e.g. a type mismatch reading the config) as
// diagnostics rather than a returned error, so the returned diagnostics follow the
// framework convention: callers append them and abort when they contain an error.
func resolvePrivateKeyPEM(ctx context.Context, config tfsdk.Config, writeOnlyPath path.Path, plain types.String) (string, diag.Diagnostics) {
	var writeOnly types.String
	diags := config.GetAttribute(ctx, writeOnlyPath, &writeOnly)
	if diags.HasError() {
		return "", diags
	}
	if !writeOnly.IsNull() {
		return writeOnly.ValueString(), diags
	}
	return plain.ValueString(), diags
}

// hashForState computes the hexadecimal representation of the SHA1 checksum of a string.
// This is used by most resources/data-sources here to compute their Unique Identifier (ID).
func hashForState(value string) string {
	if value == "" {
		return ""
	}
	hash := sha1.Sum([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(hash[:])
}

// overridableTimeFunc normally returns time.Now(),
// but it is overridden during testing to simulate an arbitrary value of "now".
var overridableTimeFunc = func() time.Time {
	return time.Now()
}

// updatedUsingPlan is to be used as part of resource.Resource `Update`.
// It takes the resource.UpdateRequest `Plan` and sets it on resource.UpdateResponse State.
//
// Use this if the planned values should just be copied over into the new state.
func updatedUsingPlan(ctx context.Context, req *resource.UpdateRequest, res *resource.UpdateResponse, model interface{}) {
	// Read the plan
	res.Diagnostics.Append(req.Plan.Get(ctx, model)...)
	if res.Diagnostics.HasError() {
		return
	}

	// Set it as the new state
	res.Diagnostics.Append(res.State.Set(ctx, model)...)
}

// requireReplaceIfStateContainsPEMString returns a planmodifier.String that triggers a
// replacement of the resource if (and only if) all the conditions of a resource.RequiresReplace are met,
// and the attribute value is a PEM string.
func requireReplaceIfStateContainsPEMString() planmodifier.String {
	description := "Attribute requires replacement if it contains a PEM string"

	return stringplanmodifier.RequiresReplaceIf(func(ctx context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
		// NOTE: If we reach this point, we know a change has been detected and that is known AND not-null

		// If the value is indeed a PEM, and
		if regexp.MustCompile(`^-----BEGIN [[:alpha:] ]+-----\n(.|\s)+\n-----END [[:alpha:] ]+-----\n?$`).MatchString(req.StateValue.ValueString()) {
			resp.RequiresReplace = true
			return
		}
	}, description, description)
}
