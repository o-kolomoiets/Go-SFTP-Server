// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"golang.org/x/crypto/ssh"
)

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
