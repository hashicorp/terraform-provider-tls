package provider

import (
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestProvider(t *testing.T) {
	if err := New().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

var testProviders = map[string]*schema.Provider{
	"tls": New(),
}

func setTimeForTest(timeStr string) func() {
	return func() {
		now = func() time.Time {
			t, _ := time.Parse(time.RFC3339, timeStr)
			return t
		}
	}
}
