package provider

import (
	"log"
	"net"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/elazarl/goproxy/ext/auth"
)

// LocalTestServer is a simple HTTP server used for testing.
type LocalTestServer struct {
	listener net.Listener
	server   *http.Server
}

// newHTTPServer creates an HTTP server that listens on a random port.
func newHTTPServer() (*LocalTestServer, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	return &LocalTestServer{
		listener: listener,
		server: &http.Server{
			Addr: listener.Addr().String(),
		},
	}, nil
}

// newHTTPProxyServer creates an HTTP Proxy server that listens on a random port.
func newHTTPProxyServer() (*LocalTestServer, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	return &LocalTestServer{
		listener: listener,
		server: &http.Server{
			Addr:    listener.Addr().String(),
			Handler: proxy,
		},
	}, nil
}

// newHTTPProxyServer creates an HTTP Proxy server that listens on a random port and expects HTTP Basic Auth.
func newHTTPProxyServerWithBasicAuth(expectedUsername, expectedPassword string) (*LocalTestServer, error) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, err
	}

	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true
	proxy.OnRequest().HandleConnect(auth.BasicConnect("restricted", func(username, password string) bool {
		return username == expectedUsername && (expectedPassword == "" || password == expectedPassword)
	}))
	return &LocalTestServer{
		listener: listener,
		server: &http.Server{
			Addr:    listener.Addr().String(),
			Handler: proxy,
		},
	}, nil
}

// ServeTLS makes the server begin listening for TLS client connections.
func (lts *LocalTestServer) ServeTLS() {
	err := lts.server.ServeTLS(lts.listener, "testdata/tls_certs/public.pem", "testdata/tls_certs/private.pem")
	if err != nil {
		log.Println("Failed to start LocalTestServer with TLS", err)
	}
}

// Serve makes the server begin listening for plain client connections.
func (lts *LocalTestServer) Serve() {
	err := lts.server.Serve(lts.listener)
	if err != nil {
		log.Println("Failed to start LocalTestServer", err)
	}
}

func (lts *LocalTestServer) Close() error {
	if err := lts.listener.Close(); err != nil {
		return err
	}
	if err := lts.server.Close(); err != nil {
		return err
	}
	return nil
}

func (lts *LocalTestServer) Address() string {
	return lts.listener.Addr().String()
}
