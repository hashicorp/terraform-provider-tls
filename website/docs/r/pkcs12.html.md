---
layout: "tls"
page_title: "TLS: tls_pkcs12"
sidebar_current: "docs-tls-resource-pkcs12"
description: |-
  Creates a PKCS#12 file.
---

# tls\_pkcs12

Generates PKCS#12 file.

This resource is intended to be used in conjunction with a Terraform provider
tha has a resource that requires a TLS certificate, such as:

* ``openstack_keymanager_secret_v1`` to create the container with the TLS certificates,
which can be used by the loadbalancer HTTPS listener.

## Example Usage

```hcl
resource "tls_private_key" "my_key" {
  algorithm   = "RSA"
}

resource "tls_self_signed_cert" "my_cert" {
  key_algorithm   = "RSA"
  private_key_pem = tls_private_key.my_key

  subject {
    common_name  = "example.com"
    organization = "ACME Examples, Inc"
  }

  validity_period_hours = 12

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

resource "tls_pkcs12" "my_p12" {
  private_key_pem = tls_private_key.my_key
  certificate_pem = tls_self_signed_cert.my_cert.cert_pem
  ca_certificate_pem = [
    tls_self_signed_cert.my_cert.cert_pem
  ]
}

resource "openstack_keymanager_secret_v1" "certificate_p12" {
  name                     = "tls_pkcs12_bundle"
  payload                  = tls_pkcs12.my_12.certificate_12
  secret_type              = "certificate"
  payload_content_type     = "application/octet-stream"
  payload_content_encoding = "base64"
}
```

## Argument Reference

The following arguments are supported:

* `private_key_pem` - (Required) PEM-encoded private key data. This can be
  read from a separate file using the ``file`` interpolation function. If the
  certificate is being generated to be used for a throwaway development
  environment or other non-critical application, the `tls_private_key` resource
  can be used to generate a TLS private key from within Terraform. Only
  an irreversable secure hash of the private key will be stored in the Terraform
  state.

* `certificate_pem` - (Required) The certificate data in PEM format.

* `ca_certificate_pem` - (Required) List of PEM-encoded certificate data for the CA.

* `certificate_p12_password` - (Optional) Password to be used when generating the PFX file
  stored in certificate_p12. Defaults to an empty string.

## Attributes Reference

The following attributes are exported:

* `certificate_p12` -The certificate, intermediate, and the private key archived as a PFX file
  (PKCS12 format, generally used by Microsoft products). The data is base64 encoded (including padding),
  and its password is configurable via the certificate_p12_password argument.

