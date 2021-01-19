package provider

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceSshKeyScan() *schema.Resource {
	return &schema.Resource{
		Read: dataSourceSshKeyScanRead,
		Schema: map[string]*schema.Schema{
			"host": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Host to ssh key scan.",
			},
			"port": {
				Type:        schema.TypeInt,
				Optional:    true,
				Default:     22,
				Description: "Port to key scan",
			},
			"public_host_key": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Result of ssh key scan.",
			},
		},
	}
}

func dataSourceSshKeyScanRead(d *schema.ResourceData, meta interface{}) error {
	host := d.Get("host").(string)
	port := d.Get("port").(int)

	hostKeyCh := make(chan string, 1)
	hostKeyError := errors.New("ignoring host key verification")
	hostKeyCallback := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		keyStr := base64.StdEncoding.EncodeToString([]byte(key.Marshal()))
		hostKeyCh <- fmt.Sprintf("%s %s", key.Type(), keyStr)
		return hostKeyError
	}

	config := &ssh.ClientConfig{
		HostKeyCallback: hostKeyCallback,
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%v", host, port), config)
	if err != nil && !strings.Contains(err.Error(), hostKeyError.Error()) {
		return err
	}

	// Authentication errors will cause client to be nil
	if client != nil {
		client.Close()
	}
	hostKey := <-hostKeyCh

	d.Set("public_host_key", fmt.Sprintf("%s %s", host, hostKey))
	d.SetId(time.Now().UTC().String())

	return nil
}
