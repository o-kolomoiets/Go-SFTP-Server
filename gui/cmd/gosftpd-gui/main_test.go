// SPDX-License-Identifier: Apache-2.0

//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAllowedPlatform(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"xcb", "xcb"},
		{"wayland", "wayland"},
		{"cocoa", "cocoa"},
		{"wayland;xcb", "wayland;xcb"},
		{"vnc", ""},
		{"vnc:size=800x600", ""},
		{"offscreen", ""},
		{"vnc;xcb", "xcb"},
		{" xcb ; eglfs", "xcb"},
		{"xcb:nograb", "xcb:nograb"},
		{"wayland-egl;minimalegl", ""},
		{"", ""},
	} {
		if got := allowedPlatform(tc.in); got != tc.want {
			t.Errorf("allowedPlatform(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSetPlatform(t *testing.T) {
	t.Setenv("QT_QPA_PLATFORM", "vnc")
	t.Setenv("QT_QPA_GENERIC_PLUGINS", "tuiotouch")
	setPlatform()
	if v, ok := os.LookupEnv("QT_QPA_GENERIC_PLUGINS"); ok {
		t.Errorf("QT_QPA_GENERIC_PLUGINS=%q kept, want it removed", v)
	}
	if v, ok := os.LookupEnv("QT_QPA_PLATFORM"); ok {
		t.Errorf("QT_QPA_PLATFORM=%q kept, want it removed", v)
	}
	t.Setenv("QT_QPA_PLATFORM", "vnc;wayland")
	setPlatform()
	if v := os.Getenv("QT_QPA_PLATFORM"); v != "wayland" {
		t.Errorf("QT_QPA_PLATFORM=%q, want wayland", v)
	}
}

// The flags that need no window.
func TestRunFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != 0 || !strings.HasPrefix(out.String(), "gosftpd-gui dev") {
		t.Errorf("--version: %d %q %q", code, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := run([]string{"extra"}, &out, &errOut); code != 2 || !strings.Contains(errOut.String(), "unexpected argument") {
		t.Errorf("an argument: %d %q", code, errOut.String())
	}
	errOut.Reset()
	if code := run([]string{"--no-such-flag"}, &out, &errOut); code != 2 {
		t.Errorf("an unknown flag: %d %q", code, errOut.String())
	}
}

// setup finds the state directory, the preferences and the lock.
func TestSetup(t *testing.T) {
	config, rt := t.TempDir(), t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	bin := filepath.Join(t.TempDir(), "gosftpd")
	a, lock, err := setup(bin)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Release() }()
	if a.PrefsPath != filepath.Join(config, "gosftpd-gui.conf") || a.G.Layout.Dir != filepath.Join(config, "gosftpd-gui") || a.G.Bin != bin {
		t.Errorf("setup: prefs %q, state %q, gosftpd %q", a.PrefsPath, a.G.Layout.Dir, a.G.Bin)
	}
	if _, _, err := setup(bin); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Errorf("a second setup: %v", err)
	}
}
