resource "tls_private_key" "ed25519-example" {
  algorithm = "ED25519"
}

resource "random_password" "pwd-example" {
  length = 40
  special = false
}

# Encrypted PEM
resource "tls_encrypted_pem" "example" {
  pem = tls_private_key.ed25519-example.private_key_pem
  password = random_password.pwd-example.result

  # optional
  cipher = "AES256"
}
