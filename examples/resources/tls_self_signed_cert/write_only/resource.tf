ephemeral "tls_private_key" "example" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "example" {
  # The private key is passed via the write-only attribute.
  # It will not be stored in the state.
  private_key_pem_wo = ephemeral.tls_private_key.example.private_key_pem

  # When using private_key_pem_wo, a version must be provided.
  # Changing this version triggers a re-creation of the certificate.
  private_key_pem_wo_version = "1"

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
