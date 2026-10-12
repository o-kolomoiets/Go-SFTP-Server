// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package sandbox

import (
	"context"
	"errors"
	"io"
)

var host kernel = noLandlock{}

// noLandlock is a system without Landlock: Start applies nothing, and
// "required" fails.
type noLandlock struct{}

var errNoLandlock = errors.New(reasonNotLinux)

func (noLandlock) supported() bool                   { return false }
func (noLandlock) lsm() (string, error)              { return "", errNoLandlock }
func (noLandlock) filtered() (bool, error)           { return false, errNoLandlock }
func (noLandlock) probe(context.Context) probeResult { return probeResult{err: errNoLandlock} }
func (noLandlock) abi() (int, error)                 { return 0, errNoLandlock }
func (noLandlock) input() (Input, error)             { return Input{}, errNoLandlock }
func (noLandlock) apply([]Rule) error                { return errNoLandlock }
func (noLandlock) selfCheck() error                  { return errNoLandlock }
func (noLandlock) releaseTerminal() error            { return errNoLandlock }

// probeChild is never started on systems without Landlock.
func probeChild(io.Writer) int { return 1 }

// ClearAmbient does nothing: ambient capabilities exist only on Linux.
func ClearAmbient() (uint64, error) { return 0, nil }
