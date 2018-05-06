---
layout: "tls"
page_title: "TLS: tls_cert_request"
sidebar_current: "docs-tls-data-source-cert-request"
description: |-
  Creates a PEM-encoded certificate request.
---

# tls\_cert\_request

Generates a *Certificate Signing Request* (CSR) in PEM format, which is the
typical format used to request a certificate from a certificate authority.

This resource is intended to be used in conjunction with a Terraform provider
for a particular certificate authority in order to provision a new certificate.
This is a *logical resource*, so it contributes only to the current Terraform
state and does not create any external managed resources.

~> **Compatibility Note** From Terraform 0.7.0 to 0.7.4 this resource was
converted to a data source, and the resource form of it was deprecated. This
turned out to be a design error since a cert request includes a random number
in the form of the signature nonce, and so the data source form of this
resource caused non-convergent configuration. The data source form is no longer
supported as of Terraform 0.7.5 and any users should return to using the
resource form.

## Example Usage

```hcl
resource "tls_cert_request" "example" {
  key_algorithm   = "ECDSA"
  private_key_pem = "${file("private_key.pem")}"

  subject {
    common_name  = "example.com"
    organization = ["ACME Examples, Inc"]
    # Specifying a simple string instead of a list of strings is deprecated
    # but is works for now
    # organization = "ACME Examples, Inc"
  }
}
```

## Argument Reference

The following arguments are supported:

* `key_algorithm` - (Required) The name of the algorithm for the key provided
in `private_key_pem`.

* `private_key_pem` - (Required) PEM-encoded private key data. This can be
read from a separate file using the ``file`` interpolation function. Only
an irreversible secure hash of the private key will be stored in the Terraform
state.

* `subject` - (Required) The subject for which a certificate is being requested. This is
a nested configuration block whose structure is described below.

* `dns_names` - (Optional) List of DNS names for which a certificate is being requested.

* `ip_addresses` - (Optional) List of IP addresses for which a certificate is being requested.

The nested `subject` block accepts the following arguments, all optional, with their meaning
corresponding to the similarly-named attributes defined in
[RFC 5280](https://tools.ietf.org/html/rfc5280#section-4.1.2.4):

* `common_name` (string)

* `organization` (list of strings)

* `organizational_unit` (list of strings)

* `street_address` (list of strings)

* `locality` (list of strings)

* `province` (list of strings)

* `country` (list of strings)

* `postal_code` (list of strings)

* `serial_number` (string)

**NOTE** In provider releases prior to 1.2.0, the `organization`, `organizational_unit`,
`locality`, `province`, `country`, and `postal_code` attributes were of type string.
In accordance with RFC 5290, these attributes now take values of type list of strings,
and using values of type string is now deprecated.

However, a simple string is currently accepted for these
attributes for compatibility reasons, and is converted internally to a list of
a single string. In the future, we may remove this compatibility feature, so please
update your configuration files.

If you have existing Terraform state that was created with previous verisons of the TLs
provider, running `terraform plan` or `terraform apply` will force any resources
dependent on a `subject` field to be destroyed and recreated. This may cause
certificates to be regenerated.

## Attributes Reference

The following attributes are exported:

* `cert_request_pem` - The certificate request data in PEM format.
