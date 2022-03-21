---
layout: "tls"
page_title: "TLS: tls_public_key"
description: |-
  Get a public key from a PEM-encoded private key.
---

# Data Source: tls_public_key

Use this data source to get the public key from a [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421)
or [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716) formatted private key,
for use in other resources.

## Example Usage

```hcl
resource "tls_private_key" "ed25519-example" {
  algorithm = "ED25519"
}

# Public key loaded from a terraform-generated private key, using the PEM (RFC 1421) format
data "tls_public_key" "private_key_pem-example" {
  private_key_pem = tls_private_key.ed25519-example.private_key_pem
}

# Public key loaded from filesystem, using the Open SSH (RFC 4716) format
data "tls_public_key" "private_key_openssh-example" {
  private_key_openssh = file("~/.ssh/id_rsa_rfc4716")
}
```

## Argument Reference

The following arguments are supported:

* `private_key_pem` - (Optional) The private key [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421)
  to use. Currently-supported algorithms for keys are `RSA`, `ECDSA` and `ED25519`.
  This is _mutually exclusive_ with `private_key_openssh`. 
  
* `private_key_openssh` - (Optional) The private key [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716)
  to use. Currently-supported algorithms for keys are `RSA`, `ECDSA` and `ED25519`.
  This is _mutually exclusive_ with `private_key_pem`.

### Limitations: `ECDSA` with `P224` elliptic curve

When providing a key that uses `ECDSA` with `P224`, the following attributes will have a value of `""` (empty string):

* `.public_key_openssh`
* `.public_key_fingerprint_md5`
* `.public_key_fingerprint_sha256`

The SSH ECC Algorithm Integration ([RFC 5656](https://datatracker.ietf.org/doc/html/rfc5656))
restricts support for elliptic curves to "nistp256", "nistp384" and "nistp521",
so these [OpenSSH](https://www.openssh.com/)-specific attributes will be left blank.

## Attributes Reference

The following attributes are exported:

* `private_key_pem` - The private key PEM, if it was provided as argument.

* `private_key_openssh` - The private key OpenSSH PEM, if it was provided as argument.

* `algorithm` - The name of the algorithm used by the given private key.
  Possible values are: `RSA`, `ECDSA` and `ED25519`.

* `public_key_pem` - The public key data in PEM format.

* `public_key_openssh` - The public key data in [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716)
  format. This is also known as
  ["Authorized Keys"](https://www.ssh.com/academy/ssh/authorized_keys/openssh#format-of-the-authorized-keys-file)
  format. This is populated only if the configured private key is supported:
  this includes all `RSA` and `ED25519` keys, as well as `ECDSA` keys with curves
  `P256`, `P384` and `P521`; as explained above, `ECDSA` with curve `P224`
  [is not supported](#limitations-ecdsa-with-p224-elliptic-curve). 

* `public_key_fingerprint_md5` - The fingerprint of the public key data in
  OpenSSH MD5 hash format, e.g. `aa:bb:cc:...`. Only available if the
  selected private key format is compatible, as per the rules for
  `public_key_openssh` and [ECDSA P224 limitations](#limitations-ecdsa-with-p224-elliptic-curve).

* `public_key_fingerprint_sha256` - The fingerprint of the public key data in
  OpenSSH SHA256 hash format, e.g. `SHA256:...`. Only available if the
  selected private key format is compatible, as per the rules for
  `public_key_openssh` and [ECDSA P224 limitations](#limitations-ecdsa-with-p224-elliptic-curve).
