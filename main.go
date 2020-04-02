package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/plugin"
	"github.com/hashicorp/terraform-provider-tls/tls"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: tls.Provider})
}
