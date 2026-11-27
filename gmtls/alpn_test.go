package gmtls

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jianlu8023/go-gmsm/x509"
)

// TestALPN_InvalidProtoLength verifies the RFC 7301 Section 3.1 constraint
// (protocol names are 1 to 255 octets) enforced by makeClientHelloGM,
// mirroring the standard-path makeClientHello validation.
func TestALPN_InvalidProtoLength(t *testing.T) {
	cfg := &Config{
		GMSupport:          NewGMSupport(),
		InsecureSkipVerify: true,
		NextProtos:         []string{strings.Repeat("a", 256)},
	}
	if _, err := makeClientHelloGM(cfg); err == nil ||
		err.Error() != "tls: invalid NextProtos value" {
		t.Fatalf("got %v", err)
	}

	// an empty protocol name is invalid as well
	cfg = &Config{
		GMSupport:          NewGMSupport(),
		InsecureSkipVerify: true,
		NextProtos:         []string{""},
	}
	if _, err := makeClientHelloGM(cfg); err == nil ||
		err.Error() != "tls: invalid NextProtos value" {
		t.Fatalf("got %v", err)
	}
}

// TestALPN_TooManyProtos verifies the 65535-octet total extension size
// limit enforced by makeClientHelloGM.
func TestALPN_TooManyProtos(t *testing.T) {
	protos := make([]string, 257)
	for i := range protos {
		protos[i] = strings.Repeat("a", 255) // 257*(1+255) > 0xffff
	}
	cfg := &Config{
		GMSupport:          NewGMSupport(),
		InsecureSkipVerify: true,
		NextProtos:         protos,
	}
	if _, err := makeClientHelloGM(cfg); err == nil ||
		err.Error() != "tls: NextProtos values too large" {
		t.Fatalf("got %v", err)
	}
}

// TestALPN_ServerPicksUnadvertised verifies RFC 7301 Section 3.2 on the
// client side: a ServerHello selecting a protocol the client never
// advertised must fail the handshake (standard library checkALPN).
//
// This needs a raw processServerHello call because no real server in this
// codebase ever selects an unadvertised protocol.
func TestALPN_ServerPicksUnadvertised(t *testing.T) {
	c := new(Conn)
	c.isClient = true
	c.buffering = true // keep the alert in sendBuf; c.conn is not wired up
	c.config = &Config{}

	hs := &clientHandshakeStateGM{
		c:           c,
		serverHello: &serverHelloMsg{alpnProtocol: "h2"},
		hello:       &clientHelloMsg{alpnProtocols: []string{"spdy/3.1"}},
	}
	if _, err := hs.processServerHello(); err == nil ||
		!strings.Contains(err.Error(), "unadvertised ALPN protocol") {
		t.Fatalf("got %v, want unadvertised ALPN protocol error", err)
	}
	if c.clientProtocol != "" {
		t.Fatalf("clientProtocol = %q, want empty", c.clientProtocol)
	}
	if len(c.sendBuf) == 0 {
		t.Fatalf("expected a handshake failure alert to be buffered for the server")
	}
}

// TestALPN_ClientAcceptsAdvertised is the happy-path counterpart of
// TestALPN_ServerPicksUnadvertised: a ServerHello selecting an advertised
// protocol must be accepted.
func TestALPN_ClientAcceptsAdvertised(t *testing.T) {
	c := new(Conn)
	c.isClient = true
	c.buffering = true // keep the alert in sendBuf; c.conn is not wired up
	c.config = &Config{}

	hs := &clientHandshakeStateGM{
		c:           c,
		serverHello: &serverHelloMsg{alpnProtocol: "h2"},
		hello:       &clientHelloMsg{alpnProtocols: []string{"spdy/3.1", "h2"}},
	}
	resumed, err := hs.processServerHello()
	if err != nil {
		t.Fatalf("got %v, want nil", err)
	}
	if resumed {
		t.Fatalf("resumed = true, want false")
	}
	if c.clientProtocol != "h2" {
		t.Fatalf("clientProtocol = %q, want %q", c.clientProtocol, "h2")
	}
	if c.clientProtocolFallback {
		t.Fatalf("clientProtocolFallback = true, want false")
	}
}

const alpnCertDir = "certs" // 由 workflow_test.go 的 TestMain 自动生成

// startServer starts a GMTLS server on a random localhost port using the
// examples auto-switch config (GMSSL dual certificates) and serves exactly
// one connection in the background. It returns the address, a channel that
// delivers the server-side handshake error (nil when the handshake
// succeeded), and a cleanup function.
func startALPNServer(t *testing.T, serverNextProtos []string) (string, <-chan error, func()) {
	t.Helper()

	sigCert, err := LoadX509KeyPair(
		filepath.Join(alpnCertDir, "sm2_sign_cert.cer"),
		filepath.Join(alpnCertDir, "sm2_sign_key.pem"))
	if err != nil {
		t.Fatalf("load sign cert: %v", err)
	}
	encCert, err := LoadX509KeyPair(
		filepath.Join(alpnCertDir, "sm2_enc_cert.cer"),
		filepath.Join(alpnCertDir, "sm2_enc_key.pem"))
	if err != nil {
		t.Fatalf("load enc cert: %v", err)
	}
	rsaCert, err := LoadX509KeyPair(
		filepath.Join(alpnCertDir, "rsa_sign.cer"),
		filepath.Join(alpnCertDir, "rsa_sign_key.pem"))
	if err != nil {
		t.Fatalf("load rsa cert: %v", err)
	}

	config, err := NewBasicAutoSwitchConfig(&sigCert, &encCert, &rsaCert)
	if err != nil {
		t.Fatalf("new auto switch config: %v", err)
	}
	config.NextProtos = serverNextProtos

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := NewListener(inner, config)

	errCh := make(chan error, 1)
	go func() {
		defer close(errCh)
		for {
			sc, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func() {
				tconn := sc.(*Conn)
				hErr := tconn.Handshake()
				_ = sc.Close()
				errCh <- hErr
			}()
		}
	}()

	done := func() { ln.Close() }
	return inner.Addr().String(), errCh, done
}

// dialClient dials the server with the given NextProtos and returns the
// connection (handshake already attempted). The returned Conn is always
// non-nil unless Dial fails at the TCP level.
func dialALPNClient(t *testing.T, addr string, clientNextProtos []string) (*Conn, error) {
	t.Helper()

	pool := x509.NewCertPool()
	caPEM, err := os.ReadFile(filepath.Join(alpnCertDir, "SM2_CA.cer"))
	if err != nil {
		t.Fatalf("read CA: %v", err)
	}
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatalf("append CA")
	}

	config := &Config{
		GMSupport:          NewGMSupport(),
		RootCAs:            pool,
		ServerName:         "localhost",
		NextProtos:         clientNextProtos,
		InsecureSkipVerify: true,
	}

	return Dial("tcp", addr, config)
}

// TestALPN_Match verifies the migrated GMSSL client ALPN extension: with
// overlapping protocol lists both sides must negotiate the server's
// first common protocol ("h2").
func TestALPN_Match(t *testing.T) {
	addr, serverErrCh, done := startALPNServer(t, []string{"h2", "http/1.1"})
	defer done()

	client, err := dialALPNClient(t, addr, []string{"h2", "http/1.1"})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	clientState := client.ConnectionState()
	if got := clientState.NegotiatedProtocol; got != "h2" {
		t.Errorf("client NegotiatedProtocol = %q, want %q", got, "h2")
	}
	if !clientState.NegotiatedProtocolIsMutual {
		t.Errorf("client NegotiatedProtocolIsMutual = false, want true")
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// TestALPN_NoCommonProtocol verifies RFC 7301 Section 3.2: when the two
// sides share no protocol, the handshake must fail on both ends.
func TestALPN_NoCommonProtocol(t *testing.T) {
	addr, serverErrCh, done := startALPNServer(t, []string{"h2"})
	defer done()

	client, err := dialALPNClient(t, addr, []string{"spdy/3.1"})
	if err == nil {
		client.Close()
		t.Fatalf("client dial succeeded, want failure when no protocol is shared")
	}
	// The server fails first and sends the no_application_protocol(120)
	// alert, so the client surfaces the remote alert error.
	if !strings.Contains(err.Error(), "no application protocol") {
		t.Fatalf("client error = %v, want the no application protocol alert", err)
	}

	select {
	case serr := <-serverErrCh:
		if serr == nil {
			t.Fatalf("server handshake succeeded, want failure when no protocol is shared")
		}
		if !strings.Contains(serr.Error(), "do not share a protocol") {
			t.Fatalf("server error = %v, want \"client and server do not share a protocol\"", serr)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for server handshake error")
	}
}

// TestALPN_NoServerProtos verifies the regression case: a server without
// NextProtos does not answer the ALPN extension and no protocol is
// negotiated; the handshake must still succeed.
func TestALPN_NoServerProtos(t *testing.T) {
	addr, serverErrCh, done := startALPNServer(t, nil)
	defer done()

	client, err := dialALPNClient(t, addr, []string{"h2"})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	if got := client.ConnectionState().NegotiatedProtocol; got != "" {
		t.Errorf("NegotiatedProtocol = %q, want empty (server configured no protocols)", got)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// TestALPN_ClientNoProtos verifies the regression case: when neither side
// uses ALPN the handshake must succeed exactly as before the change.
func TestALPN_ClientNoProtos(t *testing.T) {
	addr, serverErrCh, done := startALPNServer(t, nil)
	defer done()

	client, err := dialALPNClient(t, addr, nil)
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer client.Close()
	if got := client.ConnectionState().NegotiatedProtocol; got != "" {
		t.Errorf("NegotiatedProtocol = %q, want empty", got)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}
