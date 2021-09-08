---
layout: "tls"
page_title: "TLS: tls_certificate"
sidebar_current: "docs-tls-datasource-tls-certificate"
description: |-
  Get information about the TLS certificates securing a host.
---

# Data Source: tls_certificate

Use this data source to get information, such as SHA1 fingerprint or serial number, about the TLS certificates that
protect an HTTPS website. Note that the certificate chain isn't verified.

## Example Usage

```hcl
resource "aws_eks_cluster" "example" {
  name = "example"
}

data "tls_certificate" "example" {
  url = "${aws_eks_cluster.example.identity.0.oidc.0.issuer}"
}

resource "aws_iam_openid_connect_provider" "example" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["${data.tls_certificate.example.certificates.0.sha1_fingerprint}"]
  url             = "${aws_eks_cluster.example.identity.0.oidc.0.issuer}"
}
```

## Argument Reference

The following arguments are supported:

* `url` - (Required) The URL of the website to get the certificates from.
* `verify_chain` - (Optional) Whether to verify the certificate chain while parsing it or not


## Attributes Reference

The following attributes are exported:

* `certificates` - The certificates protecting the site, with the root of the chain first.
    * `certificates.#.not_after` - The time until which the certificate is invalid, as an
    [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.
    * `certificates.#.not_before` - The time after which the certificate is valid, as an
    [RFC3339](https://tools.ietf.org/html/rfc3339) timestamp.
    * `certificates.#.is_ca` - `true` if this certificate is a ca certificate.
    * `certificates.#.issuer` - Who verified and signed the certificate, roughly following
    [RFC2253](https://tools.ietf.org/html/rfc2253).
    * `certificates.#.public_key_algorithm` - The algorithm used to create the certificate.
    * `certificates.#.serial_number` - Number that uniquely identifies the certificate with the CA's system. The `format`
    function can be used to convert this base 10 number into other bases, such as hex.
    * `certificates.#.sha1_fingerprint` - The SHA1 fingerprint of the public key of the certificate.
    * `certificates.#.sha256_fingerprint` - The SHA256 fingerprint of the public key of the certificate.
    * `certificates.#.sha1_fingerprint_rfc4716` - The SHA1 thumbprint of the public key of the certificate in RFC4716 format.
    * `certificates.#.sha256_fingerprint_rfc4716` - The SHA256 thumbprint of the public key of the certificate in RFC4716 format.
    * `certificates.#.signature_algorithm` - The algorithm used to sign the certificate.
    * `certificates.#.subject` - The entity the certificate belongs to, roughly following
    [RFC2253](https://tools.ietf.org/html/rfc2253).
    * `certificates.#.version` - The version the certificate is in.
