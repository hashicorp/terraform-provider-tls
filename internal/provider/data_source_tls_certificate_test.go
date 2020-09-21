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
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.0.pem", `-----BEGIN CERTIFICATE-----
MIIDSTCCAjGgAwIBAgIQLYZHhf04h/2jlZsgJbq/1TANBgkqhkiG9w0BAQsFADA0
MQ0wCwYDVQQHEwRIZXJlMREwDwYDVQQKEwhUZXN0IE9yZzEQMA4GA1UEAxMHUm9v
dCBDQTAeFw0xOTExMDcxNTQ3NDhaFw0xOTEyMTcxNTQ3NDhaMDQxDTALBgNVBAcT
BEhlcmUxETAPBgNVBAoTCFRlc3QgT3JnMRAwDgYDVQQDEwdSb290IENBMIIBIjAN
BgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwMNzcNkAoCaIhaEVqPZOt53vws6K
Owx9SgdRJxFv1t51RdVg3m5NJoQsAFof1giYYP9og2J9gYp6t/ORaWOjcDF1Tt6l
/vCbQypAwIGHdx5VuJsOy79YoxQVXssNCQZFDl7iuucisuPq9xRSrE84RwTyzU+S
jUbBeyPEBs3mzekwk0pyndMala/NnkWPgHwEI2lMbvZIXCQqokhhusp85e5cdkgD
4s2/XyNk9yNTlLaaiA8413G2ABD6cvDbJI5y/Og9A1N+VHN30+qFhNXX7qZqWoiD
hQQb7CTeqRaNDS3136qPoQZ0w+3iH4Vnl6bCgOrfU1w0k+0v9xs/sEJp+wIDAQAB
o1cwVTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEwDwYDVR0T
AQH/BAUwAwEB/zAdBgNVHQ4EFgQUgFGgz37Dv+htdqoCZoI/JV+V3EQwDQYJKoZI
hvcNAQELBQADggEBALmO85dAooD1+2qhjJuLTZgESnVTS3KJQTqLQypIhyF1an3+
MMq4h3oYmN5n3dNq+8HKq06XffI6vLqmxo9Mj5CXuos60IydXiASMzRBStkRd+/P
pJ2u6SJC1+u3HaR/TYLVA5JoZ3JESLzRsM0G75eiEiZy+jQzFaNpuG54ylz4y6jk
w4sbWtwCeHIbLCU9Ee0lHb0xWrkOJnOPYrq0hlXCCqkml0HjD5jdheoRglJIUabm
eA3ZUVSXXLsWuPlItoM02+JcMJV82Hfh9w0cYq1Z44eyBJO2EMAkLP0T5GRbWA+R
0vRPQyF7Oz/Klv3ZhTwS0gzNiTmNPCXvCjZoXhc=
-----END CERTIFICATE-----
`),

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
					resource.TestCheckResourceAttr("data.tls_certificate.test", "certificates.1.pem", `-----BEGIN CERTIFICATE-----
MIIDUzCCAjugAwIBAgIRAMhMxtTgTXHTmo6ZU7OafFMwDQYJKoZIhvcNAQELBQAw
NDENMAsGA1UEBxMESGVyZTERMA8GA1UEChMIVGVzdCBPcmcxEDAOBgNVBAMTB1Jv
b3QgQ0EwHhcNMTkxMTA4MDkwMTM2WhcNMTkxMTA4MTkwMTM2WjA+MRMwEQYDVQQH
EwpFdmVyeXdoZXJlMRIwEAYDVQQKEwlDaGlsZCBDby4xEzARBgNVBAMTCkNoaWxk
IENlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQTeCu466xxnGr
CCrl823J4gGnp9AYb0laTP3uB4orXblTFq45ehDnEJXNykT+7acT8IrAjQlVQdl0
gLjNM6XjGkFQ7xRw5xi041vRrOtUzC1KxVqrcfT4WrKj6zM/MuK3hznc4NvvwdAx
Mb3Sk46yQ1PrMslsidDvhTAqXkVi3lD1bV/bpnDo3NRCldVpedE1wlR+6thXZN/Y
MggNuDdv6LDadVGlXgKw5KkEIgenGOzpX1o+GKGo5UWu1xoTHikVwEC1iVuCZax+
9FnHQO/q7SyF4Lb9d0j6vzrIAjzauGbiAsJya1GhYMF7INxzpSolzk0UYjT5Dxcq
d3VX1prxAgMBAAGjVjBUMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEF
BQcDATAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFIBRoM9+w7/obXaqAmaCPyVf
ldxEMA0GCSqGSIb3DQEBCwUAA4IBAQCuXJkT+qD3STmyDlsJOQRLBKaECH+/0mw4
mn3oMikNfneybjhao+fpwTgFup3KIrdIgbuciHfSTZzWT6mDs9bUdZZLccU6cVRh
WiX0I1eppjQyOT7PuXDsOsBUMf+et5WuGYrtKsib07q2rHPtTq72iftANtWbznfq
DsM3TQL4LuEE9V2lU2L2f3kXKrkYzLJj7R4sGck5Fo/E8eeIFm1Z5FCPcia82N+C
xDsNFvV3r8TsRH60IxFekKddI+ivepa97SvC4r+69MPyxULHNwDtSL+8T4q01LEP
VKT7dWjBK3K0xxH0SPCtlqRbGalWz4adNNHazN/x7ebK+WB9ReSM
-----END CERTIFICATE-----
`),
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
