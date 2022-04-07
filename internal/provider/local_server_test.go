package provider

import (
	"log"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
)

// LocalServerTest is a simple HTTP server used for testing.
type LocalServerTest struct {
	listener net.Listener
	server   *http.Server
}

// newHTTPServer creates an HTTP server that listens on a random port.
func newHTTPServer() (*LocalServerTest, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	return &LocalServerTest{
		listener: listener,
		server: &http.Server{
			Addr: listener.Addr().String(),
		},
	}, nil
}

// newHTTPProxyServer creates an HTTP Proxy server that listens on a random port.
func newHTTPProxyServer() (*LocalServerTest, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	return &LocalServerTest{
		listener: listener,
		server: &http.Server{
			Addr:    listener.Addr().String(),
			Handler: goproxy.NewProxyHttpServer(),
		},
	}, nil
}

// newHTTPProxyServer creates an HTTP Proxy server that listens on a random port and expects HTTP Basic Auth.
func newHTTPProxyServerWithBasicAuth(expectedUsername, expectedPassword string) (*LocalServerTest, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.OnRequest().HandleConnect(auth.BasicConnect("restricted", func(username, password string) bool {
		return username == expectedUsername && (expectedPassword == "" || password == expectedPassword)
	}))
	return &LocalServerTest{
		listener: listener,
		server: &http.Server{
			Addr:    listener.Addr().String(),
			Handler: proxy,
		},
	}, nil
}

// ServeTLS makes the server begin listening for TLS client connections.
func (lst *LocalServerTest) ServeTLS() {
	err := lst.server.ServeTLS(lst.listener, "testdata/tls_certs/public.pem", "testdata/tls_certs/private.pem")
	if err != nil {
		log.Println("Failed to start LocalServerTest with TLS", err)
	}
}

// Serve makes the server begin listening for plain client connections.
func (lst *LocalServerTest) Serve() {
	err := lst.server.Serve(lst.listener)
	if err != nil {
		log.Println("Failed to start LocalServerTest", err)
	}
}

func (lst *LocalServerTest) Close() error {
	if err := lst.listener.Close(); err != nil {
		return err
	}
	if err := lst.server.Close(); err != nil {
		return err
	}
	return nil
}

func (lst *LocalServerTest) Address() string {
	return lst.listener.Addr().String()
}
