# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

resource "tls_cert_request" "example" {
  private_key_pem = file("private_key.pem")

  subject {
    common_name  = "example.com"
    organization = "ACME Examples, Inc"
  }
}
