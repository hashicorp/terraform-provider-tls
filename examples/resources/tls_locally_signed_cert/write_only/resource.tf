ephemeral "tls_private_key" "ca" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca" {
  private_key_pem_wo         = ephemeral.tls_private_key.ca.private_key_pem
  private_key_pem_wo_version = "1"
  is_ca_certificate          = true

  subject {
    common_name  = "My Private CA"
    organization = "ACME Examples, Inc"
  }

  validity_period_hours = 12

  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

ephemeral "tls_private_key" "leaf" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "leaf" {
  private_key_pem_wo         = ephemeral.tls_private_key.leaf.private_key_pem
  private_key_pem_wo_version = "1"

  subject {
    common_name  = "example.com"
    organization = "ACME Examples, Inc"
  }
}

resource "tls_locally_signed_cert" "example" {
  cert_request_pem = tls_cert_request.leaf.cert_request_pem
  ca_cert_pem      = tls_self_signed_cert.ca.cert_pem

  # The CA private key is passed via the write-only attribute.
  # It will not be stored in the state.
  ca_private_key_pem_wo = ephemeral.tls_private_key.ca.private_key_pem

  # When using ca_private_key_pem_wo, a version must be provided.
  # Changing this version triggers a re-creation of the certificate.
  ca_private_key_pem_wo_version = "1"

  validity_period_hours = 12

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}
