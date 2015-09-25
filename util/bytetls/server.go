package bytetls

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// TLSServer ,the stuff below is lifted from the http package and adapted to provide SSL cert/key handling without needing files
func TLSServer(addr string, certPEM, keyPEM []byte, handler http.Handler, listener net.Listener) error {
	srv := &http.Server{Addr: addr, Handler: handler}
	addr = srv.Addr
	if addr == "" {
		addr = ":https"
	}
	config := &tls.Config{}
	if srv.TLSConfig != nil {
		*config = *srv.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return err
	}
	if listener == nil {
		listener, err = net.Listen("tcp", addr)
		if err != nil {
			return err
		}
	}
	tlsListener := tls.NewListener(tcpKeepAliveListener{listener.(*net.TCPListener)}, config)
	return srv.Serve(tlsListener)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted
// connections. It's used by ListenAndServe and ListenAndServeTLS so
// dead TCP connections (e.g. closing laptop mid-download) eventually
// go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
