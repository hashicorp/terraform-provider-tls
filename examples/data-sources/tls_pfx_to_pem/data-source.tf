locals {
  pfx_file_path = "../../../internal/provider/fixtures/certificate_rsa_legacy.pfx"
}

data "tls_pfx_to_pem" "this" {
  content_base64 = filebase64(local.pfx_file_path)
  password       = ""
}

resource "local_sensitive_file" "certificate_pem" {
  filename = "${path.module}/certificate.pem"
  content  = data.tls_pfx_to_pem.this.certificate_pem
}

resource "local_sensitive_file" "private_key" {
  filename = "${path.module}/private_key.pem"
  content  = data.tls_pfx_to_pem.this.private_key_pem
}
