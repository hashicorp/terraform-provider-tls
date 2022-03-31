package provider

import (
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

var testProviders = map[string]*schema.Provider{
	"tls": New(),
}

func setTimeForTest(timeStr string) func() {
	return func() {
		overridableTimeFunc = func() time.Time {
			t, _ := time.Parse(time.RFC3339, timeStr)
			return t
		}
	}
}

func TestProvider(t *testing.T) {
	if err := New().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_InvalidProxyConfig(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		Providers: testProviders,

		Steps: []resource.TestStep{
			{
				Config: `
					provider "tls" {
						proxy {
							url = "https://proxy.host.com"
							from_env = true
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile(`"proxy.0.url": conflicts with proxy.0.from_env|"proxy.0.from_env": conflicts with proxy.0.url`),
			},
			{
				Config: `
					provider "tls" {
						proxy {
							username = "user"
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile("\"proxy.0.username\": all of `proxy.0.url,proxy.0.username` must be specified"),
			},
			{
				Config: `
					provider "tls" {
						proxy {
							password = "pwd"
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile("\"proxy.0.password\": all of `proxy.0.password,proxy.0.username` must be"),
			},
			{
				Config: `
					provider "tls" {
						proxy {
							username = "user"
							password = "pwd"
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile("\"proxy.0.username\": all of `proxy.0.url,proxy.0.username` must be specified"),
			},
			{
				Config: `
					provider "tls" {
						proxy {
							username = "user"
							from_env = true
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile(`"proxy.0.from_env": conflicts with proxy.0.username`),
			},
		},
	})
}
