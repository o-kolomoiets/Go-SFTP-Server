// SPDX-License-Identifier: Apache-2.0

//go:build unix

package app

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/gui/internal/gosftpdtest"
	"github.com/o-kolomoiets/go-sftp-server/gui/internal/supervisor"
)

var testBin string

func TestMain(m *testing.M) {
	code := func() int {
		bin, clean, err := gosftpdtest.Build(filepath.Join("..", "..", ".."))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
		defer clean()
		testBin = bin
		return m.Run()
	}()
	os.Exit(code)
}

// newApp returns an App on a new state directory, and two folders.
func newApp(t *testing.T) (a *App, inbox, docs string) {
	t.Helper()
	gosftpdtest.SkipRoot(t)
	t.Setenv("HOME", t.TempDir())
	dir := t.TempDir()
	inbox, docs = filepath.Join(dir, "Inbox"), filepath.Join(dir, "Docs")
	for _, d := range []string{inbox, docs} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return &App{G: supervisor.Gosftpd{Bin: testBin, Layout: supervisor.Layout{Dir: filepath.Join(dir, "state")}}}, inbox, docs
}

// reachable is a name of the server on all interfaces that its
// known_hosts line lists: the machine's name if it resolves, else one of
// its addresses. Loopback addresses are not listed.
func reachable(t *testing.T, d supervisor.Details) string {
	t.Helper()
	if _, err := net.DefaultResolver.LookupHost(t.Context(), d.Host); err == nil {
		return d.Host
	}
	if len(d.Addresses) > 0 {
		return d.Addresses[0]
	}
	t.Skip("the server has no name or address to connect to")
	return ""
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for deadline := time.Now().Add(15 * time.Second); !ok(); {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestFormCheck(t *testing.T) {
	folders := []supervisor.Folder{{Name: "Inbox", Path: "/srv/inbox"}}
	nobody := Current{}
	someone := Current{Configured: true, People: []supervisor.Person{{Name: "alice"}}}
	for _, tc := range []struct {
		name string
		form Form
		cur  Current
		want string // "" for none
	}{
		{"no folder", Form{Port: 2022, Person: NewPerson{Name: "a", Password: "pw"}}, nobody, "choose a folder"},
		{"port 0", Form{Folders: folders, Person: NewPerson{Name: "a", Password: "pw"}}, nobody, "port"},
		{"port too big", Form{Folders: folders, Port: 70000, Person: NewPerson{Name: "a", Password: "pw"}}, nobody, "port"},
		{"nobody at all", Form{Folders: folders, Port: 2022}, nobody, "add a person"},
		{"nobody new, someone before", Form{Folders: folders, Port: 2022}, someone, ""},
		{"no name", Form{Folders: folders, Port: 2022, Person: NewPerson{Password: "pw"}}, someone, "give the person a name"},
		{"no secret", Form{Folders: folders, Port: 2022, Person: NewPerson{Name: "bob"}}, someone, "give bob a password or their public key"},
		{"both", Form{Folders: folders, Port: 2022, Person: NewPerson{Name: "bob", Password: "pw", Key: "ssh-ed25519 AAAA"}}, nobody, "not both"},
		{"line break", Form{Folders: folders, Port: 2022, Person: NewPerson{Name: "bob", Password: "a\nb"}}, nobody, "line break"},
		{"password", Form{Folders: folders, Port: 2022, Person: NewPerson{Name: "bob", Password: "pw"}}, nobody, ""},
		{"key", Form{Folders: folders, Port: 2022, Person: NewPerson{Name: "bob", Key: "ssh-ed25519 AAAA"}}, nobody, ""},
	} {
		err := tc.form.Check(tc.cur)
		if (tc.want == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: Check = %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestWithPort(t *testing.T) {
	for _, tc := range []struct {
		listen    []string
		old, port int
		want      []string
	}{
		{nil, 2022, 2200, []string{":2200"}},
		{[]string{":2022"}, 2022, 2200, []string{":2200"}},
		{[]string{"127.0.0.1:2022", "[::1]:2022", ":8022"}, 2022, 2200, []string{"127.0.0.1:2200", "[::1]:2200", ":8022"}},
		{[]string{":2022"}, 2022, 2022, []string{":2022"}},
	} {
		if got := withPort(tc.listen, tc.old, tc.port); !slices.Equal(got, tc.want) {
			t.Errorf("withPort(%q, %d, %d) = %q, want %q", tc.listen, tc.old, tc.port, got, tc.want)
		}
	}
}

func TestShare(t *testing.T) {
	a, inbox, docs := newApp(t)
	ctx := t.Context()
	cur, err := a.Load(ctx)
	if err != nil || cur.Configured {
		t.Fatalf("Load before a share = %+v, %v", cur, err)
	}
	if a.Done() != nil || a.Sharing() {
		t.Error("sharing before Start")
	}

	// The first share: a folder to upload to, a read-only one, and a
	// person with a key.
	key, pub := gosftpdtest.KeyPair(t)
	port := gosftpdtest.FreePort(t)
	form := Form{
		Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}, {Name: "Docs", Path: docs, ReadOnly: true}},
		Port:    port,
		Person:  NewPerson{Name: "partner", Key: pub},
	}
	if _, err := a.Apply(ctx, cur, form); err != nil {
		t.Fatal(err)
	}
	cur, err = a.Load(ctx)
	if err != nil || !cur.Configured || cur.Port() != port || len(cur.People) != 1 || cur.Settings.PasswordLogins {
		t.Fatalf("Load after the first share = %+v, %v", cur, err)
	}
	if p := cur.People[0]; p.Name != "partner" || p.Keys != 1 || p.Access["Inbox"] != "upload" || p.Access["Docs"] != "read" {
		t.Errorf("partner = %+v", p)
	}
	if want := []supervisor.Folder{form.Folders[1], form.Folders[0]}; !slices.Equal(cur.Settings.Folders, want) { // sorted by name
		t.Errorf("folders = %+v, want %+v", cur.Settings.Folders, want)
	}

	d, err := a.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if a.Sharing() {
			a.StopNow()
			<-a.Done()
			_ = a.Exited()
		}
	})
	if d.Port != port || !strings.HasPrefix(d.HostKeyFingerprint, "SHA256:") {
		t.Fatalf("details = %+v", d)
	}
	if _, err := a.Start(ctx, nil); !errors.Is(err, ErrSharing) {
		t.Errorf("a second Start = %v, want ErrSharing", err)
	}
	waitFor(t, "server.start", func() bool { _, err := a.Poll(); return err == nil && a.Landlock() != "" })

	// The person uploads to Inbox and reads Docs.
	file := filepath.Join(t.TempDir(), "report.pdf")
	if err := os.WriteFile(file, []byte("report"), 0o600); err != nil {
		t.Fatal(err)
	}
	gosftpdtest.SFTP(t, reachable(t, d), d.Port, d.KnownHosts, "partner", key, "put "+file+" /Inbox/report.pdf\nls /Docs\n")
	if data, err := os.ReadFile(filepath.Join(inbox, "report.pdf")); err != nil || string(data) != "report" {
		t.Errorf("uploaded file: %q, %v", data, err)
	}

	// Stop, and Exited says it stopped as asked.
	a.Stop()
	<-a.Done()
	if err := a.Exited(); err != nil {
		t.Errorf("Exited after Stop = %v", err)
	}
	if a.Sharing() {
		t.Error("sharing after Exited")
	}

	// A later share changes only what changed: another port, Docs no
	// longer shared, a person with a password. Partner loses Docs.
	port2 := gosftpdtest.FreePort(t)
	form2 := Form{
		Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}},
		Port:    port2,
		Person:  NewPerson{Name: "bob", Password: "correct horse"},
	}
	if _, err := a.Apply(ctx, cur, form2); err != nil {
		t.Fatal(err)
	}
	cur, err = a.Load(ctx)
	if err != nil || cur.Port() != port2 || len(cur.Settings.Folders) != 1 || !cur.Settings.PasswordLogins || len(cur.People) != 2 {
		t.Fatalf("Load after the second share = %+v, %v", cur, err)
	}
	for _, p := range cur.People {
		if _, ok := p.Access["Docs"]; ok || p.Access["Inbox"] != "upload" {
			t.Errorf("%s: access %v", p.Name, p.Access)
		}
	}
	// Nobody new: the folders and the port only.
	if _, err := a.Apply(ctx, cur, Form{Folders: cur.Settings.Folders, Port: port2}); err != nil {
		t.Errorf("Apply with nobody new: %v", err)
	}
	// gosftpd's own checks: a name it refuses leaves the folders written.
	if _, err := a.Apply(ctx, cur, Form{Folders: cur.Settings.Folders, Port: port2, Person: NewPerson{Name: "Bad Name", Password: "x"}}); err == nil {
		t.Error("gosftpd accepted the user name \"Bad Name\"")
	}
}

func TestStartErrors(t *testing.T) {
	a, inbox, _ := newApp(t)
	ctx := t.Context()
	_, pub := gosftpdtest.KeyPair(t)

	// A port another program holds.
	var lc net.ListenConfig
	l, err := lc.Listen(ctx, "tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	held := l.Addr().(*net.TCPAddr).Port
	if _, err := a.Apply(ctx, Current{}, Form{Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}}, Port: held, Person: NewPerson{Name: "partner", Key: pub}}); err != nil {
		t.Fatal(err)
	}
	var se *supervisor.StartError
	if _, err := a.Start(ctx, nil); !errors.As(err, &se) || se.Kind != "listen" || !strings.HasSuffix(se.Address, ":"+strconv.Itoa(held)) {
		t.Errorf("Start on a held port = %v, want a listen error", err)
	}
	if a.Sharing() {
		t.Error("sharing after a failed Start")
	}

	// Another version than the GUI's.
	a.Version = "v0.0.0-not-this"
	var ve *supervisor.VersionError
	if _, err := a.Start(ctx, nil); !errors.As(err, &ve) {
		t.Errorf("Start with another version = %v, want a VersionError", err)
	}
}

// A server that dies is reported with what it logged.
func TestUnexpectedExit(t *testing.T) {
	a, inbox, _ := newApp(t)
	ctx := t.Context()
	_, pub := gosftpdtest.KeyPair(t)
	if _, err := a.Apply(ctx, Current{}, Form{Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}}, Port: gosftpdtest.FreePort(t), Person: NewPerson{Name: "partner", Key: pub}}); err != nil {
		t.Fatal(err)
	}
	d, err := a.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(d.PID, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	<-a.Done()
	if err := a.Exited(); err == nil || !strings.Contains(err.Error(), "stopped unexpectedly") {
		t.Errorf("Exited after a kill = %v", err)
	}
}

// A GUI started after one that died waits for the server that one
// started, still draining, before it serves.
func TestWaitPrevious(t *testing.T) {
	first, inbox, _ := newApp(t)
	ctx := t.Context()
	_, pub := gosftpdtest.KeyPair(t)
	rt := t.TempDir()
	lock, err := supervisor.AcquireLock(rt)
	if err != nil {
		t.Fatal(err)
	}
	first.Lock = lock
	if _, err := first.Apply(ctx, Current{}, Form{Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}}, Port: gosftpdtest.FreePort(t), Person: NewPerson{Name: "partner", Key: pub}}); err != nil {
		t.Fatal(err)
	}
	if _, err := first.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { first.StopNow(); <-first.Done() })
	// The first GUI "dies": its lock goes, its server runs on.
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}

	second := &App{G: first.G}
	if second.Lock, err = supervisor.AcquireLock(rt); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Lock.Release() }()
	waited := make(chan int, 1)
	started := make(chan error, 1)
	go func() {
		sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		_, err := second.Start(sctx, func(pid int) { waited <- pid })
		started <- err
	}()
	select {
	case pid := <-waited:
		if pid == 0 {
			t.Error("waiting for pid 0")
		}
	case err := <-started:
		t.Fatalf("the second GUI started while the first one's server ran: %v", err)
	}
	first.Stop()
	if err := <-started; err != nil {
		t.Fatalf("Start after the previous server exited: %v", err)
	}
	second.StopNow()
	<-second.Done()
	if err := second.Exited(); err != nil {
		t.Error(err)
	}
}

// Stop now with someone connected is a stop that was asked for, not a
// crash: gosftpd leaves the second SIGTERM to its default action.
func TestStopNowWithSession(t *testing.T) {
	a, inbox, _ := newApp(t)
	ctx := t.Context()
	key, pub := gosftpdtest.KeyPair(t)
	if _, err := a.Apply(ctx, Current{}, Form{Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}}, Port: gosftpdtest.FreePort(t), Person: NewPerson{Name: "partner", Key: pub}}); err != nil {
		t.Fatal(err)
	}
	d, err := a.Start(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	gosftpdtest.Session(t, reachable(t, d), d.Port, d.KnownHosts, "partner", key)
	waitFor(t, "partner to be connected", func() bool {
		s, err := a.Poll()
		return err == nil && slices.Equal(Names(s), []string{"partner"})
	})
	a.Stop()
	a.StopNow()
	<-a.Done()
	if err := a.Exited(); err != nil {
		t.Errorf("Exited after Stop now = %v", err)
	}
	if s, _ := a.Poll(); len(s) != 0 {
		t.Errorf("connected after the exit: %v", s)
	}
}

// What was shared before is never written over unread.
func TestUnreadConfiguration(t *testing.T) {
	ctx := t.Context()
	form := func(t *testing.T, inbox string) Form {
		t.Helper()
		_, pub := gosftpdtest.KeyPair(t)
		return Form{Folders: []supervisor.Folder{{Name: "Inbox", Path: inbox}}, Port: gosftpdtest.FreePort(t), Person: NewPerson{Name: "bob", Key: pub}}
	}

	// A configuration gosftpd cannot read.
	a, inbox, _ := newApp(t)
	if _, err := a.Apply(ctx, Current{}, form(t, inbox)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(a.G.Layout.Config(), []byte("no_such_key = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Load(ctx); err == nil {
		t.Fatal("Load read a configuration gosftpd refuses")
	}
	if _, err := a.Apply(ctx, Current{}, form(t, inbox)); err == nil {
		t.Error("Apply wrote over a configuration it could not read")
	}
	if data, _ := os.ReadFile(a.G.Layout.Config()); string(data) != "no_such_key = 1\n" {
		t.Errorf("the configuration was changed: %q", data)
	}

	// People without a configuration: a first share would hand their
	// grants to the new folders of the same names.
	b, inbox2, _ := newApp(t)
	if _, err := b.Apply(ctx, Current{}, form(t, inbox2)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b.G.Layout.Config()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load(ctx); err == nil || !strings.Contains(err.Error(), "holds people") {
		t.Errorf("Load with people but no configuration = %v", err)
	}
	if _, err := b.Apply(ctx, Current{}, form(t, inbox2)); err == nil {
		t.Error("Apply shared afresh over the people of users.d")
	}
}
