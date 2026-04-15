//go:build integration_tcpspoof && windows && (amd64 || 386)

package tcpspoof

import (
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// The Windows spoofer installs the WinDivert kernel driver via SCM,
// which needs Administrator. Gate by env to match the unix suite and
// skip on access-denied so the CI matrix stays green for non-elevated
// jobs.
func requireWindowsIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("TCPSPOOF_INTEGRATION") != "1" {
		t.Skip("set TCPSPOOF_INTEGRATION=1 to run integration tests")
	}
}

func newSpooferOrSkip(t *testing.T, conn net.Conn, method Method) Spoofer {
	t.Helper()
	spoofer, err := NewSpoofer(conn, method)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			t.Skip("requires Administrator")
		}
		t.Fatalf("NewSpoofer: %v", err)
	}
	return spoofer
}

// Basic lifecycle: opening a spoofer against a live TCP conn installs
// the driver, spawns run(), then shuts down cleanly without ever
// injecting. Exercises the close path that cancels an in-flight Recv.
func TestIntegrationSpooferOpenClose(t *testing.T) {
	requireWindowsIntegration(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := listener.Accept()
		accepted <- c
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	server := <-accepted
	t.Cleanup(func() {
		if server != nil {
			server.Close()
		}
	})

	spoofer := newSpooferOrSkip(t, client, MethodWrongSequence)
	require.NoError(t, spoofer.Close())
}

// End-to-end: Conn.Write injects a fake ClientHello with a rewritten
// SNI, then forwards the real ClientHello. With wrong-sequence, the
// fake lands before the connection's send-next sequence — the peer TCP
// stack treats it as already-received and only surfaces the real bytes
// to the echo server.
func TestIntegrationConnInjectsThenForwardsRealCH(t *testing.T) {
	requireWindowsIntegration(t)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	serverReceived := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, _ := io.ReadAll(conn)
		serverReceived <- got
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	spoofer := newSpooferOrSkip(t, client, MethodWrongSequence)
	wrapped := NewConn(client, spoofer, "letsencrypt.org")

	payload, err := hex.DecodeString(realClientHello)
	require.NoError(t, err)

	n, err := wrapped.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	_ = wrapped.Close()

	select {
	case got := <-serverReceived:
		require.Equal(t, payload, got,
			"server must receive real ClientHello unchanged (wrong-sequence fake must be dropped)")
	case <-time.After(5 * time.Second):
		t.Fatal("echo server did not receive real ClientHello within 5s")
	}
}

// Inject before any kernel payload: stages the fake, then Write flushes
// the real CH. Same terminal expectation as the Conn variant but via the
// Spoofer primitive directly.
func TestIntegrationSpooferInjectThenWrite(t *testing.T) {
	requireWindowsIntegration(t)

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })

	serverReceived := make(chan []byte, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, _ := io.ReadAll(conn)
		serverReceived <- got
	}()

	client, err := net.Dial("tcp4", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })

	spoofer := newSpooferOrSkip(t, client, MethodWrongSequence)
	t.Cleanup(func() { spoofer.Close() })

	payload, err := hex.DecodeString(realClientHello)
	require.NoError(t, err)
	fake, err := rewriteSNI(payload, "letsencrypt.org")
	require.NoError(t, err)
	require.NoError(t, spoofer.Inject(fake))

	n, err := client.Write(payload)
	require.NoError(t, err)
	require.Equal(t, len(payload), n)
	_ = client.Close()

	select {
	case got := <-serverReceived:
		require.Equal(t, payload, got)
	case <-time.After(5 * time.Second):
		t.Fatal("echo server did not receive real ClientHello within 5s")
	}
}
