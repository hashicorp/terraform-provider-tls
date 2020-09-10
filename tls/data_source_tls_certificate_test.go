package tls

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"log"
	"net"
	"net/http"
	"testing"
)

func TestAccTlsCertificate_dataSource(t *testing.T) {
	server, host, err := newTlsServer()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go server.serve()

	resource.UnitTest(t, resource.TestCase{
		Providers: testProviders,

		Steps: []resource.TestStep{
			{

				Config: fmt.Sprintf(`
data "tls_certificate" "test" {
  url = "https://%s"
  verify_chain = false
}
`, host),
				Check: resource.ComposeAggregateTestCheckFunc(
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
				),
			},
		},
	})
}

type tlsServer struct {
	listener net.Listener
	server   *http.Server
}

func newTlsServer() (*tlsServer, string, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, "", err
	}

	return &tlsServer{
		listener: listener,
		server: &http.Server{
			Addr: listener.Addr().String(),
		},
	}, listener.Addr().String(), nil
}

func (t *tlsServer) serve() {
	err := t.server.ServeTLS(t.listener, "testdata/tls_certs/public.pem", "testdata/tls_certs/private.pem")
	if err != nil {
		log.Println("Failed to serve TLS server", err)
	}
}

func (t *tlsServer) Close() error {
	if err := t.listener.Close(); err != nil {
		return err
	}
	if err := t.server.Close(); err != nil {
		return err
	}
	return nil
}
