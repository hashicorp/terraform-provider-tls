package provider

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
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
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.sha256_fingerprint", "fbab4a817b07545e5a674208f0fd4b6975305d0bd65419d23f6ce8476865f7a1"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.sha1_fingerprint_rfc4716", "58:29:a9:bc:c5:7f:31:77:19:c5:c9:8d:1f:48:d6:c9:95:7c:b4:4e"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.sha256_fingerprint_rfc4716", "fb:ab:4a:81:7b:07:54:5e:5a:67:42:08:f0:fd:4b:69:75:30:5d:0b:d6:54:19:d2:3f:6c:e8:47:68:65:f7:a1"),

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
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.sha256_fingerprint", "66d69bb2324b5fdef01ee5c59d6bdc1fce1a0db62ee6ba897a4bc1fdace20520"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.sha1_fingerprint_rfc4716", "61:b6:56:24:42:7d:75:b6:11:69:10:08:36:90:4e:44:36:4d:f8:17"),
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.sha256_fingerprint_rfc4716", "66:d6:9b:b2:32:4b:5f:de:f0:1e:e5:c5:9d:6b:dc:1f:ce:1a:0d:b6:2e:e6:ba:89:7a:4b:c1:fd:ac:e2:05:20"),

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
