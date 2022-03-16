---
layout: "tls"
page_title: "TLS: tls_self_signed_cert"
description: |-
  Creates a self-signed TLS certificate in PEM format.
---

# tls\_self\_signed\_cert

Generates a *self-signed* TLS certificate in PEM format, which is the typical
format used to configure TLS server software.

Self-signed certificates are generally not trusted by client software such
as web browsers. Therefore clients are likely to generate trust warnings when
connecting to a server that has a self-signed certificate. Self-signed certificates
are usually used only in development environments or apps deployed internally
to an organization.

This resource is intended to be used in conjunction with a Terraform provider
that has a resource that requires a TLS certificate, such as:

* ``aws_iam_server_certificate`` to register certificates for use with AWS *Elastic
Load Balancer*, *Elastic Beanstalk*, *CloudFront* or *OpsWorks*.

* ``heroku_cert`` to register certificates for applications deployed on Heroku.


## Automatic Renewal

This resource considers its instances to have been deleted after either their validity
periods ends or the early renewal period is reached. At this time, applying the
Terraform configuration will cause a new certificate to be generated for the instance.

Therefore in a development environment with frequent deployments it may be convenient
to set a relatively-short expiration time and use early renewal to automatically provision
a new certificate when the current one is about to expire.

The creation of a new certificate may of course cause dependent resources to be updated
or replaced, depending on the lifecycle rules applying to those resources.
