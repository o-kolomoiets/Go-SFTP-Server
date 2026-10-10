// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
	"github.com/o-kolomoiets/go-sftp-server/internal/hostkey"
	"github.com/o-kolomoiets/go-sftp-server/internal/server"
)

// hostKeyFile is one key file of a host key, with its certificate.
type hostKeyFile struct {
	path      string
	signer    ssh.Signer // nil when only the public key could be read (inspect)
	pub       ssh.PublicKey
	generated bool
	fromPub   bool             // pub was read from "<path>.pub"
	cert      *ssh.Certificate // with host_certificates
	served    ssh.Signer       // cert with signer, for a current key
}

// hostKey is a configured host key file P with its next and previous keys
// (ADR 0008).
type hostKey struct {
	cur       hostKeyFile
	next, old *hostKeyFile
}

// hostKeys are the host keys of a configuration.
type hostKeys []hostKey

type hostKeyOptions struct {
	generate bool // create a missing key (at start, with host_key_auto_generate)
	certs    bool // read certificates (server.host_certificates)
	// lenient leaves out next and previous keys and certificates that
	// cannot be used, with a warning (reload).
	lenient bool
	// inspect needs only public keys: "<file>.pub" when the private key is
	// not readable, and nothing for a key that serve would generate.
	inspect bool
}

// loadHostKeys reads the host keys at paths with their next and previous
// keys and, with o.certs, their certificates.
func loadHostKeys(paths []string, o hostKeyOptions) (hostKeys, []string, error) {
	var (
		keys  hostKeys
		warns []string
		errs  []error
	)
	problem := func(err error) {
		if o.lenient {
			warns = append(warns, err.Error()+"; left out")
		} else {
			errs = append(errs, err)
		}
	}
	for _, p := range paths {
		cur, err := loadKeyFile(p, o, true)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if cur == nil {
			continue // generated at start
		}
		hk := hostKey{cur: *cur}
		for _, f := range []struct {
			path string
			dst  **hostKeyFile
		}{{hostkey.Next(p), &hk.next}, {hostkey.Old(p), &hk.old}} {
			if _, err := os.Lstat(f.path); err != nil {
				continue
			}
			kf, err := loadKeyFile(f.path, o, false)
			if err != nil {
				problem(err)
				continue
			}
			*f.dst = kf
		}
		if o.certs {
			for _, kf := range []*hostKeyFile{&hk.cur, hk.next} {
				if kf == nil {
					continue
				}
				warn, err := kf.loadCert(kf == &hk.cur)
				if err != nil {
					problem(err)
				}
				if warn != "" {
					warns = append(warns, warn)
				}
			}
		}
		keys = append(keys, hk)
	}
	if err := keys.check(problem); err != nil {
		errs = append(errs, err)
	}
	return keys, warns, errors.Join(errs...)
}

// loadKeyFile reads a private key file, which must be safe like a host key.
// It returns nil for a current key that serve would generate (inspect).
func loadKeyFile(path string, o hostKeyOptions, current bool) (*hostKeyFile, error) {
	if current && o.generate {
		_, err := os.Lstat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist) && o.inspect:
			if !exists(hostkey.Next(path)) && !exists(hostkey.Old(path)) {
				return nil, nil
			}
		case errors.Is(err, fs.ErrNotExist):
			k, generated, err := hostkey.LoadOrGenerate(path)
			if err != nil {
				return nil, err
			}
			return &hostKeyFile{path: path, signer: k, pub: k.PublicKey(), generated: generated}, nil
		}
	}
	if err := config.CheckOwner(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) && current {
			return nil, fmt.Errorf("host key %s does not exist", path)
		}
		return nil, err
	}
	k, err := hostkey.Load(path)
	if err == nil {
		return &hostKeyFile{path: path, signer: k, pub: k.PublicKey()}, nil
	}
	if o.inspect && errors.Is(err, fs.ErrPermission) {
		if pub, perr := readPublicKey(path + ".pub"); perr == nil {
			return &hostKeyFile{path: path, pub: pub, fromPub: true}, nil
		}
	}
	return nil, err
}

// loadCert reads the certificate of kf, served with a current key. It
// returns a warning when there is none.
func (kf *hostKeyFile) loadCert(current bool) (warning string, err error) {
	path := hostkey.Cert(kf.path)
	if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
		if current {
			return fmt.Sprintf("host key %s has no certificate (%s): clients that trust only the CA cannot verify it", kf.path, path), nil
		}
		return fmt.Sprintf("next host key %s has no certificate (%s): certify it before rotate --finish", kf.path, path), nil
	}
	if err := config.CheckOwner(path); err != nil {
		return "", err
	}
	cert, err := hostkey.LoadCertificate(path, kf.pub)
	if err != nil {
		return "", fmt.Errorf("host certificate %w", err)
	}
	kf.cert = cert
	if current && kf.signer != nil {
		if kf.served, err = ssh.NewCertSigner(cert, kf.signer); err != nil {
			return "", fmt.Errorf("host certificate %s: %w", path, err)
		}
	}
	return "", nil
}

// check refuses two current keys of one type, of which x/crypto would use
// one, and a key given twice, which makes OpenSSH abandon an update. A
// next or previous key given twice is a problem and is left out.
func (ks hostKeys) check(problem func(error)) error {
	types := map[string]string{}
	seen := map[string]string{}
	var errs []error
	for _, k := range ks {
		t := k.cur.pub.Type()
		if prev, ok := types[t]; ok {
			errs = append(errs, fmt.Errorf("host keys %s and %s are both of type %s; only one would be used", prev, k.cur.path, t))
		}
		types[t] = k.cur.path
		blob := string(k.cur.pub.Marshal())
		if prev, ok := seen[blob]; ok {
			errs = append(errs, fmt.Errorf("host keys %s and %s hold the same key", prev, k.cur.path))
		}
		seen[blob] = k.cur.path
	}
	for i := range ks {
		for _, f := range []**hostKeyFile{&ks[i].next, &ks[i].old} {
			if *f == nil {
				continue
			}
			blob := string((*f).pub.Marshal())
			if prev, ok := seen[blob]; ok {
				problem(fmt.Errorf("%s holds the same key as %s", (*f).path, prev))
				*f = nil
				continue
			}
			seen[blob] = (*f).path
		}
	}
	return errors.Join(errs...)
}

// apply sets the host keys of a server configuration.
func (ks hostKeys) apply(cfg *server.Config) {
	cfg.HostKeys, cfg.HostCertificates, cfg.AnnouncedKeys = nil, nil, nil
	for _, k := range ks {
		cfg.HostKeys = append(cfg.HostKeys, k.cur.signer)
		if k.cur.served != nil {
			cfg.HostCertificates = append(cfg.HostCertificates, k.cur.served)
		}
		for _, f := range []*hostKeyFile{k.next, k.old} {
			if f != nil {
				cfg.AnnouncedKeys = append(cfg.AnnouncedKeys, f.signer)
			}
		}
	}
}

// hostKeyEntry describes a key file for the log.
type hostKeyEntry struct {
	role, path, fingerprint, cert string
}

func (ks hostKeys) entries() []hostKeyEntry {
	var es []hostKeyEntry
	add := func(role string, f *hostKeyFile) {
		if f == nil {
			return
		}
		e := hostKeyEntry{role: role, path: f.path, fingerprint: hostkey.Fingerprint(f.pub)}
		if f.cert != nil {
			e.cert = ssh.FingerprintSHA256(f.cert)
		}
		es = append(es, e)
	}
	for i := range ks {
		add("current", &ks[i].cur)
		add("next", ks[i].next)
		add("previous", ks[i].old)
	}
	return es
}

// logChanges logs the host keys when they differ from prev.
func (ks hostKeys) logChanges(ctx context.Context, log *slog.Logger, prev hostKeys) {
	cur, old := ks.entries(), prev.entries()
	if len(cur) == len(old) {
		same := true
		for i := range cur {
			same = same && cur[i] == old[i]
		}
		if same {
			return
		}
	}
	for _, e := range cur {
		args := []any{"role", e.role, "fingerprint", e.fingerprint, "path", e.path}
		if e.cert != "" {
			args = append(args, "certificate", e.cert)
		}
		log.InfoContext(ctx, "host key", args...)
	}
}

// certs returns the certificates of the current keys, for watchHostCerts.
func (ks hostKeys) certs() []hostCert {
	var cs []hostCert
	for _, k := range ks {
		if k.cur.cert != nil {
			cs = append(cs, hostCert{hostkey.Cert(k.cur.path), k.cur.cert})
		}
	}
	return cs
}

type hostCert struct {
	path string
	cert *ssh.Certificate
}

// logCertNotice logs what a certificate's state says, if anything.
func logCertNotice(ctx context.Context, log *slog.Logger, c hostCert, state hostkey.CertValidity) {
	args := []any{"path", c.path, "valid_until", formatCertTime(hostkey.ValidUntil(c.cert))}
	switch state {
	case hostkey.CertValid:
	case hostkey.CertExpiring:
		log.WarnContext(ctx, "host certificate expires soon; renew it, replace the file and reload", args...)
	case hostkey.CertExpired:
		log.ErrorContext(ctx, "host certificate expired; it is no longer offered: renew it, replace the file and reload", args...)
	case hostkey.CertNotYetValid:
		log.WarnContext(ctx, "host certificate is not valid yet; it is offered from its start", append(args, "valid_from", formatCertTime(hostkey.ValidFrom(c.cert)))...)
	}
}

// certRepeat is how often a certificate problem is logged again.
const certRepeat = 24 * time.Hour

// watchHostCerts logs host certificates that expire soon, have expired or
// are not valid yet: at once, after every reload (a value on reloaded),
// when their state changes, and once a day while it lasts.
func watchHostCerts(ctx context.Context, current func() []hostCert, reloaded <-chan struct{}, log *slog.Logger, tick time.Duration) {
	type seen struct {
		state  hostkey.CertValidity
		logged time.Time
	}
	last := map[string]seen{} // by certificate fingerprint
	check := func(force bool) {
		now := time.Now()
		present := map[string]bool{}
		for _, c := range current() {
			fp := ssh.FingerprintSHA256(c.cert)
			present[fp] = true
			state := hostkey.Validity(c.cert, now)
			prev, known := last[fp]
			if state != hostkey.CertValid && (force || !known || state != prev.state || now.Sub(prev.logged) >= certRepeat) {
				logCertNotice(ctx, log, c, state)
				prev.logged = now
			}
			prev.state = state
			last[fp] = prev
		}
		for fp := range last {
			if !present[fp] {
				delete(last, fp)
			}
		}
	}
	check(true)
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-reloaded:
			check(true)
		case <-t.C:
			check(false)
		}
	}
}

func formatCertTime(t time.Time) string {
	if t.IsZero() {
		return "forever"
	}
	return t.Format(time.RFC3339)
}

// describeCert summarizes a certificate in one line.
func describeCert(c *ssh.Certificate) string {
	from, until := hostkey.ValidFrom(c), hostkey.ValidUntil(c)
	valid := "valid forever"
	switch {
	case !from.IsZero() && !until.IsZero():
		valid = "valid " + from.Format(time.RFC3339) + " to " + until.Format(time.RFC3339)
	case !until.IsZero():
		valid = "valid until " + until.Format(time.RFC3339)
	case !from.IsZero():
		valid = "valid from " + from.Format(time.RFC3339)
	}
	return fmt.Sprintf("principals %s, %s, CA %s", strings.Join(c.ValidPrincipals, ","), valid, ssh.FingerprintSHA256(c.SignatureKey))
}

// keyLabel is a key's type and fingerprint, as the banner shows them.
func keyLabel(k ssh.PublicKey) string {
	return strings.ToUpper(strings.TrimPrefix(k.Type(), "ssh-")) + " " + hostkey.Fingerprint(k)
}

func readPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return key, nil
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
