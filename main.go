package main

import (
	"github.com/hashicorp/terraform/plugin"
	"github.com/kaidence/terraform-provider-tls/tls"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: tls.Provider})
}
