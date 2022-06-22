package provider

import (
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
)

func setTimeForTest(timeStr string) func() {
	return func() {
		overridableTimeFunc = func() time.Time {
			t, _ := time.Parse(time.RFC3339, timeStr)
			return t
		}
	}
}

func protoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"tls": providerserver.NewProtocol6WithError(New()),
	}
}

func providerVersion340() map[string]resource.ExternalProvider {
	return map[string]resource.ExternalProvider{
		"tls": {
			VersionConstraint: "3.4.0",
			Source:            "hashicorp/tls",
		},
	}
}

func TestProvider_InvalidProxyConfig(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					provider "tls" {
						proxy = {
							url = "https://proxy.host.com"
							from_env = true
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile(`"proxy.url" cannot be specified when "proxy.from_env" is specified|"proxy.from_env" cannot be specified when "proxy.url" is specified`),
			},
			{
				Config: `
					provider "tls" {
						proxy = {
							username = "user"
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile(`"proxy.url" must be specified when "proxy.username" is specified`),
			},
			{
				Config: `
					provider "tls" {
						proxy = {
							password = "pwd"
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile(`"proxy.username" must be specified when "proxy.password" is specified`),
			},
			{
				Config: `
					provider "tls" {
						proxy = {
							username = "user"
							password = "pwd"
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile(`"proxy.url" must be specified when "proxy.username" is specified`),
			},
			{
				Config: `
					provider "tls" {
						proxy = {
							username = "user"
							from_env = true
						}
					}
					resource "tls_private_key" "test" {
						algorithm = "ED25519"
					}
				`,
				ExpectError: regexp.MustCompile(`"proxy.username" cannot be specified when "proxy.from_env" is specified|"proxy.url" must be specified when "proxy.username" is specified`),
			},
		},
	})
}
