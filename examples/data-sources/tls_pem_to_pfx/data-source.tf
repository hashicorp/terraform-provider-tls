locals {
  certificate_path = "${path.module}/../../../internal/provider/fixtures/certificate_rsa_legacy.pem"
  private_key_path = "${path.module}/../../../internal/provider/fixtures/private_key_rsa_legacy.pem"
}

data "tls_pem_to_pfx" "this" {
  password_pfx    = ""
  certificate_pem = file(local.certificate_path)
  private_key_pem = file(local.private_key_path)
}

resource "local_sensitive_file" "example" {
  filename       = "${path.module}/output.pfx"
  content_base64 = data.tls_pem_to_pfx.this.certificate_pfx
}
