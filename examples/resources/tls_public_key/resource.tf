# Generate an ephemeral private key (never stored in state)
ephemeral "tls_private_key" "example" {
  algorithm = "ED25519"
}

# Extract the public key using write-only attributes for the private key input
resource "tls_public_key" "example" {
  private_key_pem_wo     = ephemeral.tls_private_key.example.private_key_pem
  private_key_wo_version = 1
}

# Use the public key in a resource that requires a non-ephemeral value
resource "github_repository_deploy_key" "example" {
  title      = "Deploy key"
  repository = "my-repo"
  key        = tls_public_key.example.public_key_openssh
  read_only  = true
}

# Store the private key securely using a write-only attribute
resource "aws_secretsmanager_secret" "example" {
  name = "my-deploy-key"
}

resource "aws_secretsmanager_secret_version" "example" {
  secret_id                = aws_secretsmanager_secret.example.id
  secret_string_wo         = ephemeral.tls_private_key.example.private_key_pem
  secret_string_wo_version = tls_public_key.example.private_key_wo_version
}
