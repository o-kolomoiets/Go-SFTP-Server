// SPDX-License-Identifier: Apache-2.0

package sftpd

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/o-kolomoiets/go-sftp-server/internal/vfs"
)

// reader is an open download. pkg/sftp calls TransferError before Close
// when the session ends with the handle still open.
type reader struct {
	h     *Handler
	f     *os.File
	path  string
	start time.Time
	n     atomic.Int64

	mu      sync.Mutex
	aborted bool
	once    sync.Once
}

func (r *reader) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.f.ReadAt(p, off)
	r.n.Add(int64(n))
	if err != nil && !errors.Is(err, io.EOF) {
		r.h.log.Debug("read failed", "path", r.path, "err", err)
		_, st := toStatus(err)
		return n, st
	}
	return n, err
}

func (r *reader) TransferError(error) {
	r.mu.Lock()
	r.aborted = true
	r.mu.Unlock()
}

func (r *reader) Close() error {
	var err error
	r.once.Do(func() {
		err = r.f.Close()
		r.h.release()
		r.mu.Lock()
		result := "ok"
		if r.aborted {
			result = "aborted"
		}
		r.mu.Unlock()
		r.h.audit.Event("fs.download",
			slog.String("path", r.path),
			slog.Int64("bytes", r.n.Load()),
			slog.Int64("duration_ms", time.Since(r.start).Milliseconds()),
			slog.String("result", result))
	})
	return err
}

// writer is an open upload.
type writer struct {
	h         *Handler
	wh        *vfs.WriteHandle
	requested string
	flags     string
	start     time.Time

	mu      sync.Mutex
	aborted bool
	denied  atomic.Bool // a write was refused (append-only guard, max_file_size)
	once    sync.Once
}

func (w *writer) WriteAt(p []byte, off int64) (int, error) {
	n, err := w.wh.WriteAt(p, off)
	if err != nil {
		if (errors.Is(err, vfs.ErrImmutable) || errors.Is(err, vfs.ErrTooLarge)) && !w.denied.Swap(true) {
			return n, w.h.fail("fs.upload", w.wh.Path(), err) // one fs.denied per upload
		}
		w.h.log.Debug("write failed", "path", w.wh.Path(), "err", err)
		_, st := toStatus(err)
		return n, st
	}
	return n, nil
}

func (w *writer) TransferError(error) {
	w.mu.Lock()
	w.aborted = true
	w.mu.Unlock()
}

func (w *writer) Close() error {
	var err error
	w.once.Do(func() {
		w.mu.Lock()
		aborted := w.aborted
		w.mu.Unlock()
		err = w.wh.Close(aborted)
		w.h.release()
		result := "ok"
		switch {
		case aborted:
			result = "aborted"
		case w.denied.Load(), w.wh.Refused():
			result = "denied"
		case err != nil:
			// An atomic upload is published on close, by the conflict policy.
			if r, _ := toStatus(err); r == "denied" {
				result = "denied"
			} else {
				result = "error"
			}
		}
		attrs := []slog.Attr{
			slog.String("path", w.requested),
			slog.String("final_path", w.wh.Path()),
			slog.String("conflict", w.wh.Conflict()),
			slog.String("open_flags", w.flags),
			slog.Int64("bytes", w.wh.Written()),
		}
		if off, ok := w.wh.StartOffset(); ok {
			attrs = append(attrs, slog.Int64("start_offset", off))
		}
		if v := w.wh.Version(); v != "" {
			attrs = append(attrs, slog.String("version_path", v))
		}
		attrs = append(attrs,
			slog.Int64("duration_ms", time.Since(w.start).Milliseconds()),
			slog.String("result", result))
		w.h.audit.Event("fs.upload", attrs...)
		if err != nil {
			_, err = toStatus(err)
		}
	})
	return err
}
