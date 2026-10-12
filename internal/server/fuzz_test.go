// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/pires/go-proxyproto"
	"golang.org/x/crypto/ssh"
)

// FuzzProxyHeader: whatever a trusted proxy sends, readProxyHeader does
// not panic; a header it accepts is at most 107 bytes (v1) or 16 + 4096
// (v2), gives TCP addresses with a client that is not this host's (the peer
// is remote), and the bytes after it arrive unchanged. Whatever any peer
// sends first, the first-bytes check fails exactly the streams that begin
// with a PROXY signature and passes the others unchanged.
func FuzzProxyHeader(f *testing.F) {
	f.Add(v2For(f, client))
	f.Add(append(v2For(f, client), "SSH-2.0-x\r\n"...))
	f.Add(v2Proxy(f, proxyproto.TCPv6, "[2001:db8::7]:51000", "[2001:db8::1]:22"))
	f.Add([]byte("PROXY TCP4 203.0.113.7 192.0.2.1 51000 22\r\nSSH-2.0-x\r\n"))
	f.Add([]byte("PROXY TCP6 203.0.113.7 2001:db8::1 51000 22\r\n"))
	f.Add([]byte("PROXY UNKNOWN\r\n"))
	f.Add(localV2)
	f.Add(rawV2(0x21, 0x12, tcp4Payload))
	f.Add(rawV2(0x21, 0x31, make([]byte, 216)))
	f.Add(rawV2(0x21, 0x11, append(bytes.Clone(tcp4Payload), 0x05, 0, 2, 'i', 'd')))
	f.Add(v2For(f, "127.0.0.1:1"))
	f.Add([]byte("SSH-2.0-OpenSSH_10.0\r\n"))
	f.Add([]byte("PROX"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// The fuzzer minimizes each input that finds new coverage in time
		// quadratic in its length: a few long ones would take a whole
		// smoke run. Short inputs reach every path, a v2 length above the
		// limit included; TestReadProxyHeader has the 4 KiB headers.
		if len(data) > 2*headerBufferSize {
			return
		}
		conn, err := readProxyHeader(fromProxy(proxyPeer, data))
		switch he, isHeader := errors.AsType[*headerError](err); {
		case err == nil:
			rest, _ := io.ReadAll(conn)
			n := len(data) - len(rest)
			if !bytes.HasSuffix(data, rest) || n <= 0 ||
				bytes.HasPrefix(data, proxyproto.SIGV1) && n > 107 || bytes.HasPrefix(data, proxyproto.SIGV2) && n > 16+4096 {
				t.Fatalf("a header of %d bytes, then %d of %d bytes", n, len(rest), len(data))
			}
			for _, a := range []net.Addr{conn.RemoteAddr(), conn.LocalAddr()} {
				ta, ok := a.(*net.TCPAddr)
				if !ok {
					t.Fatalf("address %v (%T)", a, a)
				}
				if _, ok := netip.AddrFromSlice(ta.IP); !ok || ta.Zone != "" {
					t.Fatalf("address %v", ta)
				}
			}
			if ip, _ := netip.AddrFromSlice(conn.RemoteAddr().(*net.TCPAddr).IP); thisHost(ip.Unmap()) {
				t.Fatalf("a remote proxy relayed the client %v", ip)
			}
		case errors.Is(err, errNothingReceived):
			if len(data) > 0 {
				t.Fatalf("%d bytes taken for nothing", len(data))
			}
		case !isHeader || he.got == "" || he.hint == "":
			t.Fatalf("error %v", err)
		}

		signature := bytes.HasPrefix(data, proxyproto.SIGV1) || bytes.HasPrefix(data, proxyproto.SIGV2)
		var check headerCheck
		found := false
		for i := 0; i < len(data) && !found; i++ {
			found = check.scan(data[i : i+1])
		}
		rc := &readConn{Conn: readerConn{r: bytes.NewReader(data)}}
		got, err := io.ReadAll(rc)
		if found != signature || signature != errors.Is(err, errClientHeader) || !signature && !bytes.Equal(got, data) {
			t.Fatalf("signature %v: found %v, read %q, %v", signature, found, got, err)
		}
	})
}

// FuzzHostKeyProof: a proof request is answered only when it lists
// announced keys, each once, and nothing else; the keys to prove are
// exactly those listed, in order.
func FuzzHostKeyProof(f *testing.F) {
	p := &hostKeyProofs{}
	for i := range 3 {
		s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{byte(i + 1)}, ed25519.SeedSize)))
		if err != nil {
			f.Fatal(err)
		}
		p.keys = append(p.keys, s)
		p.blobs = append(p.blobs, s.PublicKey().Marshal())
	}
	f.Add(appendString(nil, p.blobs[0]))
	f.Add(appendString(appendString(nil, p.blobs[2]), p.blobs[0]))
	f.Add(appendString(appendString(nil, p.blobs[1]), p.blobs[1]))
	f.Add([]byte{0, 0, 0, 51, 0})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, payload []byte) {
		keys, err := p.requested(payload)
		if err != nil {
			return
		}
		if len(keys) == 0 || len(keys) > len(p.keys) {
			t.Fatalf("%d keys to prove", len(keys))
		}
		var enc []byte
		seen := map[ssh.Signer]bool{}
		for _, k := range keys {
			if seen[k] {
				t.Fatal("a key to prove twice")
			}
			seen[k] = true
			enc = appendString(enc, k.PublicKey().Marshal())
		}
		if !bytes.Equal(enc, payload) {
			t.Fatalf("payload %x answered as %x", payload, enc)
		}
	})
}
