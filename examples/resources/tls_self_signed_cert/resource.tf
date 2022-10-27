#resource "tls_self_signed_cert" "example" {
#  private_key_pem = file("private_key.pem")
#
#  subject {
#    common_name  = "example.com"
#    organization = "ACME Examples, Inc"
#  }
#
#  validity_period_hours = 12
#
#  allowed_uses = [
#    "key_encipherment",
#    "digital_signature",
#    "server_auth",
#  ]
#}

#terraform {
#  required_providers {
#    tls = {
#      source  = "hashicorp/tls"
#      version = "3.4.0"
#    }
#  }
#}

resource "tls_private_key" "example" {
  algorithm = "ECDSA"
}

resource "tls_self_signed_cert" "example" {
  private_key_pem   = tls_private_key.example.private_key_pem
  is_ca_certificate = true

  subject {
    organization = "Example"
  }

  # 3 Years
  validity_period_hours = 24 * 365 * 3

  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}
