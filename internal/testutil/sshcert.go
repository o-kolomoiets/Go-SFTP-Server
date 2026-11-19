// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"io"

	"golang.org/x/crypto/ssh"
)

// SignCert signs c with authority as c.SignCert does, without its refusal
// of a certificate with no principals or an empty one. A CA can still issue
// those, so the tests make them to check that gosftpd refuses them.
func SignCert(c *ssh.Certificate, rand io.Reader, authority ssh.Signer) error {
	c.Nonce = make([]byte, 32)
	if _, err := io.ReadFull(rand, c.Nonce); err != nil {
		return err
	}
	c.SignatureKey = authority.PublicKey()
	c.Signature = nil
	data := c.Marshal()
	data = data[:len(data)-4] // the length of the missing signature

	var sig *ssh.Signature
	var err error
	switch a := authority.(type) {
	case ssh.MultiAlgorithmSigner:
		sig, err = a.SignWithAlgorithm(rand, data, a.Algorithms()[0])
	case ssh.AlgorithmSigner:
		if a.PublicKey().Type() == ssh.KeyAlgoRSA {
			sig, err = a.SignWithAlgorithm(rand, data, ssh.KeyAlgoRSASHA512)
		} else {
			sig, err = a.Sign(rand, data)
		}
	default:
		sig, err = authority.Sign(rand, data)
	}
	if err != nil {
		return err
	}
	c.Signature = sig
	return nil
}
