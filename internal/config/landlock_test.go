// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateLandlock(t *testing.T) {
	t.Parallel()
	const webhook = "[[hooks]]\nname = \"w\"\non = [\"fs.upload\"]\nwebhook = { url = \"https://x\", secret_file = \"s\" }\n"
	const exec = "[[hooks]]\nname = \"e\"\non = [\"fs.upload\"]\nexec = { argv = [\"/bin/true\"] }\n"
	cases := []struct {
		name, landlock, hooks string
		err                   string // "" for none
	}{
		{"default", "", "", ""},
		{"auto", "auto", "", ""},
		{"off with an exec hook", "off", exec, ""},
		{"required", "required", webhook, ""},
		{"auto with an exec hook", "auto", exec, ""},
		{"required with an exec hook", "required", webhook + exec, `server.landlock: "required" cannot be used with exec hooks (hooks[1].exec)`},
		{"unknown", "on", "", `server.landlock: unknown mode "on" (want auto, off, required)`},
		{"case", "Auto", "", `unknown mode "Auto"`},
	}
	for _, tc := range cases {
		c, _ := hookConfig(t, tc.hooks)
		if tc.landlock != "" {
			c.Server.Landlock = tc.landlock
		}
		_, err := c.Validate()
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: Validate = %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: Validate = %v, want %q", tc.name, err, tc.err)
		}
	}

	if d := Default(); d.Server.Landlock != LandlockAuto {
		t.Errorf("the default is %q", d.Server.Landlock)
	}
	c, _ := load(t, "config_version = 1\n[server]\nlandlock = \"off\"\n")
	if c.Server.Landlock != LandlockOff {
		t.Errorf("server.landlock from the file = %q", c.Server.Landlock)
	}
}

func TestExecHook(t *testing.T) {
	t.Parallel()
	c := Default()
	if i := c.ExecHook(); i != -1 {
		t.Errorf("no hooks: ExecHook = %d", i)
	}
	c.Hooks = []*Hook{nil, {Webhook: &HookWebhook{}}, {Exec: &HookExec{}}, {Exec: &HookExec{}}}
	if i := c.ExecHook(); i != 2 {
		t.Errorf("ExecHook = %d, want 2", i)
	}
}
