# Terraform Provider: TLS

[![Test](https://github.com/hashicorp/terraform-provider-tls/actions/workflows/test.yml/badge.svg)](https://github.com/hashicorp/terraform-provider-tls/actions/workflows/test.yml)

The TLS provider provides utilities for working with *Transport Layer Security*
keys and certificates. It provides resources that
allow private keys, certificates and certificate requests to be
created as part of a Terraform deployment.

## Documentation

Official documentation on how to use this provider can be found on the 
[Terraform Registry](https://registry.terraform.io/providers/hashicorp/tls/latest/docs).

This document will focus on the development aspects of the provider.

## Requirements

* [Terraform](https://www.terraform.io/downloads) (>= 0.12)
* [Go](https://go.dev/doc/install) (1.17)
* [GNU Make](https://www.gnu.org/software/make/)
* [golangci-lint](https://golangci-lint.run/usage/install/#local-installation) (optional)

## Building

1. `git clone` this repository and `cd` into its directory
2. `make` will trigger the Golang build

The provided `GNUmakefile` defines additional commands generally useful during development,
like for running tests, generating documentation, code formatting and linting.
Taking a look at it's content is recommended.

### Generating documentation

This provider uses [terraform-plugin-docs](https://github.com/hashicorp/terraform-plugin-docs/)
to generate documentation and store it in the `docs/` directory.
Once a release is cut, the Terraform Registry will download the documentation from `docs/`
and associate it with the release version. Read more about how this works on the
[official page](https://www.terraform.io/registry/providers/docs).

So, it's important that every change that is merged into the default branch, is accompanied
by a regeneration of the documentation: `make generate` will do the trick.

If your change causes the content in `docs/` to change, please ensure your PR includes it,
or our testing automation will detect the mismatch and fail.

## Releasing

The release process is automated via GitHub Actions,
and it's defined in the Workflow [release.yml](./.github/workflows/release.yml).

Each release is cut by pushing a [semantically versioned](https://semver.org/)
tag to the default branch. Read more about how this works on the 
[official page](https://www.terraform.io/registry/providers/publishing#creating-a-github-release).

## License

[Mozilla Public License v2.0](./LICENSE)
