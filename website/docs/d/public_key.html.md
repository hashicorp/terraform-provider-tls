---
layout: "tls"
page_title: "TLS: tls_public_key"
sidebar_current: "docs-tls-datasource-public-key"
description: |-
  Get a public key from a PEM-encoded private key.
---

# Data Source: tls_public_key

Use this data source to get the public key from a PEM-encoded private key for use in other
resources.

## Example Usage

```hcl
data "tls_public_key" "example" {
  private_key_pem = "${file("~/.ssh/id_rsa")}"
}
```

## Argument Reference

The following arguments are supported:

* `private_key_pem` - (Required) The private key to use. Currently-supported key types are "RSA" or "ECDSA".


## Attributes Reference

The following attributes are exported:

* `private_key_pem` - The private key data in PEM format.
* `public_key_pem` - The public key data in PEM format.
* `public_key_openssh` - The public key data in OpenSSH `authorized_keys`
  format, if the selected private key format is compatible. All RSA keys
  are supported, and ECDSA keys with curves "P256", "P384" and "P521"
  are supported. This attribute is empty if an incompatible ECDSA curve
  is selected.
* `public_key_fingerprint_md5` - The md5 hash of the public key data in
  OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. Only available if the
  selected private key format is compatible, as per the rules for
  `public_key_openssh`.
