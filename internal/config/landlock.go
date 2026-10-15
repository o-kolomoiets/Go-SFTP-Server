// SPDX-License-Identifier: Apache-2.0

package config

import "strings"

// Landlock modes, the values of server.landlock (ADR 0011).
const (
	// LandlockAuto applies Landlock where it can be used and says why not
	// elsewhere.
	LandlockAuto = "auto"
	// LandlockOff never applies it.
	LandlockOff = "off"
	// LandlockRequired fails the start where it cannot be applied.
	LandlockRequired = "required"
)

// LandlockModes are the accepted values of server.landlock.
var LandlockModes = []string{LandlockAuto, LandlockOff, LandlockRequired}

func (c *Config) validateLandlock(p *problems) {
	switch c.Server.Landlock {
	case LandlockAuto, LandlockOff:
	case LandlockRequired:
		// Landlock is not applied while exec hooks are configured: a hook
		// needs the loader, its libraries and whatever it touches.
		if i := c.ExecHook(); i >= 0 {
			p.errorf("server.landlock", "%q cannot be used with exec hooks (%s): Landlock is not applied while one is configured; use a webhook, or %q",
				LandlockRequired, hookKey(i, "exec"), LandlockAuto)
		}
	default:
		p.errorf("server.landlock", "unknown mode %q (want %s)", c.Server.Landlock, strings.Join(LandlockModes, ", "))
	}
}

// ExecHook returns the index of the first exec hook in [[hooks]], or -1.
func (c *Config) ExecHook() int {
	for i, h := range c.Hooks {
		if h != nil && h.Exec != nil {
			return i
		}
	}
	return -1
}
