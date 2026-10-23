// SPDX-License-Identifier: Apache-2.0

// Command gendocs writes the man pages and shell completions of gosftpd
// into a directory (ADR 0012):
//
//	DIR/man/gosftpd.1.gz, DIR/man/gosftpd-COMMAND.1.gz   one page per command
//	DIR/completions/gosftpd.bash, _gosftpd, gosftpd.fish
//
// It replaces DIR/man and DIR/completions. The pages are dated by
// SOURCE_DATE_EPOCH, read in UTC, and compressed without a file name or
// time, so the same commit gives the same files. make generate runs it
// through go generate:
//
//	go run ./internal/cli/gendocs DIR
package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/spf13/pflag"

	"github.com/o-kolomoiets/go-sftp-server/internal/cli"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gendocs DIR")
		os.Exit(2)
	}
	date, err := sourceDate(os.Getenv("SOURCE_DATE_EPOCH"), time.Now())
	if err == nil {
		err = generate(os.Args[1], date)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
}

// sourceDate returns the time of SOURCE_DATE_EPOCH, or now when it is not
// set, in UTC: cobra would read the variable in the local time zone, where
// a page could show another month.
func sourceDate(epoch string, now time.Time) (time.Time, error) {
	if epoch == "" {
		return now.UTC(), nil
	}
	n, err := strconv.ParseInt(epoch, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, fmt.Errorf("SOURCE_DATE_EPOCH=%q is not a number of seconds since 1970", epoch)
	}
	return time.Unix(n, 0).UTC(), nil
}

// completions are the scripts, from cobra's generators rather than from
// running a binary, which may be built for another system.
var completions = []struct {
	file string
	gen  func(*cobra.Command, io.Writer) error
}{
	{"gosftpd.bash", func(c *cobra.Command, w io.Writer) error { return c.GenBashCompletionV2(w, true) }},
	{"_gosftpd", (*cobra.Command).GenZshCompletion},
	{"gosftpd.fish", func(c *cobra.Command, w io.Writer) error { return c.GenFishCompletion(w, true) }},
}

// escapeTags keeps md2man, which reads the help texts as Markdown, from
// taking a placeholder such as <user config dir> for an HTML tag and
// dropping it.
var escapeTags = strings.NewReplacer("<", `\<`, ">", `\>`)

// manText prepares a command's long help for md2man: lines indented with
// spaces, such as a table, go into a code block, which keeps them as they
// are; lines indented with a tab are one already (cobra's own texts); the
// other lines are escaped.
func manText(s string) string {
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	for i, l := range lines {
		switch {
		case strings.HasPrefix(l, " "):
			if i > 0 && lines[i-1] != "" && !strings.HasPrefix(lines[i-1], " ") {
				out = append(out, "") // a code block starts after a blank line
			}
			out = append(out, "    "+l)
		case strings.HasPrefix(l, "\t"):
			out = append(out, l)
		default:
			out = append(out, escapeTags.Replace(l))
		}
	}
	return strings.Join(out, "\n")
}

// generate replaces dir/man and dir/completions.
func generate(dir string, date time.Time) error {
	man, comp := filepath.Join(dir, "man"), filepath.Join(dir, "completions")
	for _, d := range []string{man, comp} {
		if err := os.RemoveAll(d); err != nil {
			return err
		}
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := genMan(man, date); err != nil {
		return err
	}
	root := cli.NewRootCommand()
	for _, s := range completions {
		var buf bytes.Buffer
		if err := s.gen(root, &buf); err != nil {
			return fmt.Errorf("%s: %w", s.file, err)
		}
		if err := os.WriteFile(filepath.Join(comp, s.file), buf.Bytes(), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// genMan writes a page for each command into dir.
func genMan(dir string, date time.Time) error {
	root := cli.NewRootCommand()
	// cobra adds the completion command when gosftpd runs; it gets pages
	// too.
	root.InitDefaultCompletionCmd()
	seen := map[*pflag.Flag]bool{} // a persistent flag is shared
	for _, c := range commands(root) {
		c.DisableAutoGenTag = true // a "HISTORY" section with the date
		c.Short, c.Long = escapeTags.Replace(c.Short), manText(c.Long)
		c.Flags().VisitAll(func(f *pflag.Flag) {
			if !seen[f] {
				seen[f] = true
				f.Usage = escapeTags.Replace(f.Usage)
			}
		})
	}
	header := &doc.GenManHeader{Section: "1", Date: &date, Source: "gosftpd", Manual: "gosftpd manual"}
	if err := doc.GenManTree(root, header, dir); err != nil {
		return err
	}
	return gzipPages(dir)
}

// commands returns root and all its descendants.
func commands(root *cobra.Command) []*cobra.Command {
	var all []*cobra.Command
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		all = append(all, c)
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	return all
}

// gzipPages replaces each page in dir with PAGE.gz, which has neither a
// file name nor a time in its header (as gzip -n writes it).
func gzipPages(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".1") {
			continue
		}
		page := filepath.Join(dir, e.Name())
		data, err := os.ReadFile(page)
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
		if err != nil {
			return err
		}
		if _, err := zw.Write(data); err != nil {
			return err
		}
		if err := zw.Close(); err != nil {
			return err
		}
		if err := os.WriteFile(page+".gz", buf.Bytes(), 0o644); err != nil {
			return err
		}
		if err := os.Remove(page); err != nil {
			return err
		}
	}
	return nil
}
