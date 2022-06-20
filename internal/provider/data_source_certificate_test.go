package provider

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-provider-tls/internal/provider/fixtures"
	tu "github.com/hashicorp/terraform-provider-tls/internal/provider/testutils"
)

func TestAccDataSourceCertificate_CertificateContent(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_certificate" "test" {
					  content = file("fixtures/certificate.pem")
					}
				`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.#", "1"),

					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.signature_algorithm", "SHA256-RSA"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.public_key_algorithm", "RSA"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.serial_number", "266244246501122064554217434340898012243"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.is_ca", "false"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.version", "3"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.issuer", "CN=Root CA,O=Test Org,L=Here"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.subject", "CN=Child Cert,O=Child Co.,L=Everywhere"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.not_before", "2019-11-08T09:01:36Z"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.not_after", "2019-11-08T19:01:36Z"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.sha1_fingerprint", "61b65624427d75b61169100836904e44364df817"),
					tu.TestCheckPEMFormat("data.tls_certificate.test", "certificates.0.cert_pem", PreambleCertificate.String()),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.cert_pem", strings.TrimSpace(fixtures.TestTlsDataSourceCertFromContent)+"\n"),
				),
			},
		},
	})
}

func TestAccDataSourceCertificate_CertificateContentNegativeTests(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{
				Config: `
					data "tls_certificate" "test" {
					  content = "not a pem"
					}
				`,
				ExpectError: regexp.MustCompile("Failed to decoded PEM"),
			},
			{
				Config: `
					data "tls_certificate" "test" {
					  content = file("fixtures/private.pem")
					}
				`,
				ExpectError: regexp.MustCompile("Unexpected PEM preamble"),
			},
			{
				Config: `
					data "tls_certificate" "test" {
					  content = file("fixtures/private.pem")
					  url     = "https://www.hashicorp.com"
					}
				`,
				ExpectError: regexp.MustCompile(`More than one attribute out of "content,url" has been set`),
			},
			{
				Config: `
					data "tls_certificate" "test" {}
				`,
				ExpectError: regexp.MustCompile("No attribute out of \"content,url\" has been set"),
			},
		},
	})
}

func TestAccDataSourceCertificate_HTTPSScheme(t *testing.T) {
	server, err := tu.NewHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServeTLS()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, server.Address()),
				Check: localTestCertificateChainCheckFunc(),
			},
		},
	})
}

func TestAccDataSourceCertificate_TLSScheme(t *testing.T) {
	server, err := tu.NewHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServeTLS()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
					data "tls_certificate" "test" {
					  url = "tls://%s"
					  verify_chain = false
					}
				`, server.Address()),
				Check: localTestCertificateChainCheckFunc(),
			},
		},
	})
}

func TestAccDataSourceCertificate_HTTPSSchemeViaProxy(t *testing.T) {
	server, err := tu.NewHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServeTLS()

	proxy, err := tu.NewHTTPProxyServer()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go proxy.Serve()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
					provider "tls" {
						proxy = {
							url = "http://%s"
						}
					}

					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, proxy.Address(), server.Address()),
				Check: localTestCertificateChainCheckFunc(),
			},
		},
	})
}

func TestAccDataSourceCertificate_HTTPSSchemeViaProxyWithUsernameAuth(t *testing.T) {
	server, err := tu.NewHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServeTLS()

	proxyUsername := "proxyUser"
	proxy, err := tu.NewHTTPProxyServerWithBasicAuth(proxyUsername, "")
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go proxy.Serve()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
					provider "tls" {
						proxy = {
							url = "http://%s"
							username = "%s"
						}
					}
			
					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, proxy.Address(), proxyUsername, server.Address()),
				Check: localTestCertificateChainCheckFunc(),
			},
			{

				Config: fmt.Sprintf(`
					provider "tls" {
						proxy = {
							url = "http://%s"
							username = "wrong-username"
						}
					}

					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, proxy.Address(), server.Address()),
				ExpectError: regexp.MustCompile("Proxy Authentication Required"),
			},
		},
	})
}

func TestAccDataSourceCertificate_HTTPSSchemeViaProxyWithUsernameAndPasswordAuth(t *testing.T) {
	server, err := tu.NewHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServeTLS()

	proxyUsername := "proxyUser"
	proxyPassword := "proxyPwd"
	proxy, err := tu.NewHTTPProxyServerWithBasicAuth(proxyUsername, proxyPassword)
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go proxy.Serve()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
					provider "tls" {
						proxy = {
							url = "http://%s"
							username = "%s"
							password = "%s"
						}
					}

					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, proxy.Address(), proxyUsername, proxyPassword, server.Address()),
				Check: localTestCertificateChainCheckFunc(),
			},
			{

				Config: fmt.Sprintf(`
					provider "tls" {
						proxy = {
							url = "http://%s"
							username = "%s"
							password = "wrong-password"
						}
					}

					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, proxy.Address(), proxyUsername, server.Address()),
				ExpectError: regexp.MustCompile("Proxy Authentication Required"),
			},
		},
	})
}

func TestAccDataSourceCertificate_HTTPSSchemeViaProxyFromEnv(t *testing.T) {
	server, err := tu.NewHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServeTLS()

	proxy, err := tu.NewHTTPProxyServer()
	if err != nil {
		t.Fatal(err)
	}
	defer proxy.Close()
	go proxy.Serve()
	t.Setenv("HTTP_PROXY", fmt.Sprintf("http://%s", proxy.Address()))

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
					provider "tls" {
						proxy = {
							from_env = true
						}
					}

					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, server.Address()),
				Check: localTestCertificateChainCheckFunc(),
			},
			{

				Config: fmt.Sprintf(`
					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, server.Address()),
				Check: localTestCertificateChainCheckFunc(),
			},
		},
	})
}

func TestAccDataSourceCertificate_HTTPSSchemeViaProxyButNoProxyAvailable(t *testing.T) {
	server, err := tu.NewHTTPServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.ServeTLS()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
					provider "tls" {
						proxy = {
							url = "http://localhost:65535"
						}
					}

					data "tls_certificate" "test" {
					  url = "https://%s"
					  verify_chain = false
					}
				`, server.Address()),
				ExpectError: regexp.MustCompile(`failed to fetch certificates from URL 'https': Get "https://\[::\]:\d+":(.|\s)*proxyconnect tcp: dial tcp \[::1\]:65535`),
			},
		},
	})
}

func localTestCertificateChainCheckFunc() resource.TestCheckFunc {
	return resource.ComposeAggregateTestCheckFunc(
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.#", "2"),

		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.signature_algorithm", "SHA256-RSA"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.public_key_algorithm", "RSA"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.serial_number", "60512478256160404377639062250777657301"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.is_ca", "true"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.version", "3"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.issuer", "CN=Root CA,O=Test Org,L=Here"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.subject", "CN=Root CA,O=Test Org,L=Here"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.not_before", "2019-11-07T15:47:48Z"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.not_after", "2019-12-17T15:47:48Z"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.sha1_fingerprint", "5829a9bcc57f317719c5c98d1f48d6c9957cb44e"),
		tu.TestCheckPEMFormat("data.tls_certificate.test", "certificates.0.cert_pem", PreambleCertificate.String()),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.cert_pem", strings.TrimSpace(fixtures.TestTlsDataSourceCertFromURL00)+"\n"),

		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.signature_algorithm", "SHA256-RSA"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.public_key_algorithm", "RSA"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.serial_number", "266244246501122064554217434340898012243"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.is_ca", "false"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.version", "3"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.issuer", "CN=Root CA,O=Test Org,L=Here"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.subject", "CN=Child Cert,O=Child Co.,L=Everywhere"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.not_before", "2019-11-08T09:01:36Z"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.not_after", "2019-11-08T19:01:36Z"),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.sha1_fingerprint", "61b65624427d75b61169100836904e44364df817"),
		tu.TestCheckPEMFormat("data.tls_certificate.test", "certificates.1.cert_pem", PreambleCertificate.String()),
		resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.cert_pem", strings.TrimSpace(fixtures.TestTlsDataSourceCertFromURL01)+"\n"),
	)
}

func TestAccDataSourceCertificate_MalformedURL(t *testing.T) {
	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6ProviderFactories(),

		Steps: []resource.TestStep{
			{

				Config: `
					data "tls_certificate" "test" {
						url = "http://no.https.scheme.com"
						verify_chain = false
					}
				`,
				ExpectError: regexp.MustCompile(`Invalid URL scheme`),
			},
			{

				Config: `
					data "tls_certificate" "test" {
						url = "unknown://unknown.scheme.com"
						verify_chain = false
					}
				`,
				ExpectError: regexp.MustCompile(`Invalid URL scheme`),
			},
			{

				Config: `
					data "tls_certificate" "test" {
						url = "tls://host.without.port.com"
						verify_chain = false
					}
				`,
				ExpectError: regexp.MustCompile(`Port missing from URL: tls://host.without.port.com`),
			},
			{

				Config: `
					data "tls_certificate" "test" {
						url = "ftp://ftp.scheme.com"
						verify_chain = false
					}
				`,
				ExpectError: regexp.MustCompile(`Invalid URL scheme`),
			},
			{

				Config: `
					data "tls_certificate" "test" {
						url = "1.2.3.4"
						verify_chain = false
					}
				`,
				ExpectError: regexp.MustCompile(`URL "1.2.3.4" contains no host`),
			},
			{

				Config: `
					data "tls_certificate" "test" {
						url = "not-a-url-at-all"
						verify_chain = false
					}
				`,
				ExpectError: regexp.MustCompile(`URL "not-a-url-at-all" contains no host`),
			},
		},
	})
}
