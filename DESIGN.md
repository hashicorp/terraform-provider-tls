# TLS Provider Design

The TLS Provider offers a small surface area compared to other providers (like
[AWS](https://registry.terraform.io/providers/hashicorp/aws/latest),
[Google](https://registry.terraform.io/providers/hashicorp/google/latest),
[Azure](https://registry.terraform.io/providers/hashicorp/azurerm/latest), ...),
and focuses on covering the needs of working with entities like
keys and certificates, that are part of
[Transport Security Layer](https://en.wikipedia.org/wiki/Transport_Layer_Security).

Below we have a collection of _Goals_, _Patterns_ and _Taboos_: they represent the guiding principles applied during
the development of this provider. Some are in place, others are ongoing processes, others are still just inspirational.
 
## Goals

* Support [cryptography](https://en.wikipedia.org/wiki/Cryptography) _primitives_ necessary to Terraform configurations
* Provide managed resourced and data sources to manipulate and interact with **Keys, Certificates and Certificate Requests**
* Support file and data formats widely used in the industry: this means sticking with open and well documented standards
* Support cryptography key algorithms in line with widely used software
* Offer a comprehensive documentation of the offering
* Highlight intended and unadvisable usages

## Patterns

Specific to this provider:

* **Consistency**: once a format or algorithm is adopted, all resources and data sources should support it (if appropriate)
* **Stick with Golang [crypto](https://pkg.go.dev/crypto)**: cryptography is a non-trivial subject, and not all
  provider maintainers can also be cryptography and security experts. When in doubt, it's preferred to stick with
  the functionalities covered by this library, given its wide use across the Golang community.
* **`PEM` and `OpenSSH PEM`**: Entities that support [PEM (RFC 1421)](https://datatracker.ietf.org/doc/html/rfc1421)
  should also support [OpenSSH PEM (RFC 4716)](https://datatracker.ietf.org/doc/html/rfc4716), unless there is a good
  reason not to.
* **No ["security by obscurity"](https://en.wikipedia.org/wiki/Security_through_obscurity)**: We should be clear
  in implementation and documentation that this provider doesn't provide "security" per se, but it's up to the
  practitioner to ensure it, by setting in place the right infrastructure, like storing the Terraform state in
  accordance with [recommendations](https://www.terraform.io/language/state/sensitive-data#recommendations).

General to development:

* **Avoid repetition**: the entities managed can sometimes require similar pieces of logic and/or schema to be realised.
  When this happens it's important to keep the code shared in communal sections, so to avoid having to modify code
  in multiple places when they start changing.
* **Test expectations as well as bugs**: While it's typical to write tests to exercise a new functionality, it's key
  to also provide tests for issues that get identified and fixed, so to prove resolution as well as avoid regression.
* **Automate boring tasks**: Processes that are manual, repetitive and can be automated, should be.
  In addition to be a time-saving practice, this ensures consistency and reduces human error (ex. static code analysis).
* **Semantic versioning**: Adhering to HashiCorp's own
  [Versioning Specification](https://www.terraform.io/plugin/sdkv2/best-practices/versioning#versioning-specification)
  ensures we provide a consistent practitioner experience, and a clear process to deprecation and decommission. 

## Taboos

* Supporting formats or algorithms that are specific to a _niche_, or that don't have yet a wide adoption.
* Introducing dependencies that can't offer a provable quality track record,
  or that don't have a healthy community around them.
