---
layout: "tls"
page_title: "TLS: tls_locally_signed_cert"
description: |-
  Creates a locally-signed TLS certificate in PEM format.
---

# tls\_locally\_signed\_cert

Generates a TLS certificate using a *Certificate Signing Request* (CSR) and
signs it with a provided certificate authority (CA) private key.

Locally-signed certificates are generally only trusted by client software when
setup to use the provided CA. They are normally used in development environments
or when deployed internally to an organization.


## Argument Reference

The following arguments are supported:

* `cert_request_pem` - (Required) PEM-encoded request certificate data.

* `ca_key_algorithm` - (Required) The name of the algorithm for the key provided
  in `ca_private_key_pem`.

* `ca_private_key_pem` - (Required) PEM-encoded private key data for the CA.
  This can be read from a separate file using the ``file`` interpolation
  function.

* `ca_cert_pem` - (Required) PEM-encoded certificate data for the CA.


## Automatic Renewal

This resource considers its instances to have been deleted after either their validity
periods ends or the early renewal period is reached. At this time, applying the
Terraform configuration will cause a new certificate to be generated for the instance.

Therefore in a development environment with frequent deployments it may be convenient
to set a relatively-short expiration time and use early renewal to automatically provision
a new certificate when the current one is about to expire.

The creation of a new certificate may of course cause dependent resources to be updated
or replaced, depending on the lifecycle rules applying to those resources.
