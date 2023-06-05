# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

data "tls_certificate" "example_content" {
  content = file("example.pem")
}