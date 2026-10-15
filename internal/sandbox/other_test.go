// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"

	"github.com/o-kolomoiets/go-sftp-server/internal/config"
)

// helperMain has nothing to do where Landlock does not exist.
func helperMain() {}

// TestStartWithoutLandlock: elsewhere than on Linux Start applies nothing
// and server.start gets no landlock field; "required" fails the start.
func TestStartWithoutLandlock(t *testing.T) {
	t.Parallel()
	for mode, required := range map[string]bool{config.LandlockAuto: false, config.LandlockOff: false, config.LandlockRequired: true} {
		c := config.Default()
		c.Server.Landlock = mode
		var log bytes.Buffer
		res, err := Start(t.Context(), Options{Config: c, Log: slog.New(slog.NewTextHandler(&log, nil))})
		if _, ok := errors.AsType[*RequiredError](err); ok != required || !required && err != nil {
			t.Errorf("%s: err = %v", mode, err)
		}
		if res.Status != "" || res.Ruleset != nil || log.Len() != 0 {
			t.Errorf("%s: %+v, log %q", mode, res, log.String())
		}
	}
	if cleared, err := ClearAmbient(); cleared != 0 || err != nil {
		t.Errorf("ClearAmbient = %d, %v", cleared, err)
	}
	if probeChild(nil) != 1 {
		t.Error("the probe child ran")
	}
	c := config.Default()
	c.Audit.Output = "audit.jsonl"
	if warns, err := Preview(c); warns != nil || err != nil {
		t.Errorf("Preview = %q, %v", warns, err)
	}
}
