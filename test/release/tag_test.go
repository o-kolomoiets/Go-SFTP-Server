// SPDX-License-Identifier: Apache-2.0

package release

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const (
	botName  = "github-actions[bot]"
	botEmail = "41898282+github-actions[bot]@users.noreply.github.com"
)

// ciOK returns a check run named ci-ok.
func ciOK(app, status, conclusion string) checkRun {
	r := checkRun{Name: "ci-ok", Status: status}
	r.App.Slug = app
	if conclusion != "" {
		r.Conclusion = &conclusion
	}
	return r
}

// checks sets the check runs of a commit.
func (f *fakeGitHub) checks(commit string, runs ...checkRun) {
	f.t.Helper()
	data, err := json.Marshal(runs)
	if err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.dir, "checks-"+commit+".json"), data, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

// A CHANGELOG.md with entries under Unreleased and a section for 0.5.0.
const tagChangelog = `# Changelog

## [Unreleased]

### Added

- Next.

## [0.5.0] - 2026-11-02

- Final.

## [0.4.0] - 2026-10-17

- Old.
`

// TestTagRelease runs .github/scripts/tag-release.sh as tag.yml does, on
// the second commit of a fake repository, and checks what it creates and
// starts.
func TestTagRelease(t *testing.T) {
	t.Parallel()
	// A tag on the commit to tag, or on the one before it.
	type tag struct {
		name           string
		tagger, email  string // an annotated tag's; lightweight when empty
		annotatedByBot bool   // annotated by github-actions[bot]
		onFirstCommit  bool
	}
	success := []checkRun{ciOK("github-actions", "completed", "success")}
	for _, tt := range []struct {
		name      string
		version   string
		tags      []tag
		checks    []checkRun // ci-ok on the commit to tag; success when nil
		noChecks  bool       // no check run at all
		changelog string     // tagChangelog when empty
		ref       string     // GITHUB_REF, refs/heads/main when empty
		fail      [][2]string
		code      int
		stderr    string // a part of standard error
		existing  bool   // the tag exists from an earlier run: dispatch only
	}{
		{
			name:    "the first rc",
			version: "0.5.0-rc.1",
			tags:    []tag{{name: "v0.4.0", onFirstCommit: true}, {name: "vtest"}, {name: "v0.9.0-dev"}},
		},
		{
			name:    "the final on its rc's commit",
			version: "0.5.0",
			tags:    []tag{{name: "v0.4.0", onFirstCommit: true}, {name: "v0.5.0-rc.1", annotatedByBot: true}},
		},
		{
			name:    "a first release",
			version: "0.4.0",
		},
		{
			name:    "the next rc",
			version: "0.5.0-rc.10",
			tags:    []tag{{name: "v0.5.0-rc.9", onFirstCommit: true, annotatedByBot: true}},
		},
		{
			name:    "a version below the highest",
			version: "0.4.1-rc.1",
			tags:    []tag{{name: "v0.4.0", onFirstCommit: true}, {name: "v0.5.0", onFirstCommit: true}},
			code:    1, stderr: "v0.4.1-rc.1 is not higher than every release tag: v0.5.0 exists",
		},
		{
			name:    "an rc after its final",
			version: "0.5.0-rc.2",
			tags:    []tag{{name: "v0.5.0-rc.1", onFirstCommit: true}, {name: "v0.5.0", onFirstCommit: true}},
			code:    1, stderr: "v0.5.0-rc.2 is not higher than every release tag: v0.5.0 exists",
		},
		{
			name:    "rc.9 after rc.10",
			version: "0.5.0-rc.9",
			tags:    []tag{{name: "v0.5.0-rc.10", onFirstCommit: true}},
			code:    1, stderr: "v0.5.0-rc.10 exists",
		},
		{
			name:     "a re-run after a failed dispatch",
			version:  "0.5.0-rc.1",
			tags:     []tag{{name: "v0.4.0", onFirstCommit: true}, {name: "v0.5.0-rc.1", annotatedByBot: true}},
			existing: true,
		},
		{
			name:    "the bot's tag on another commit",
			version: "0.5.0-rc.1",
			tags:    []tag{{name: "v0.5.0-rc.1", annotatedByBot: true, onFirstCommit: true}},
			code:    1, stderr: "v0.5.0-rc.1 exists already, and is not the annotated tag of github-actions[bot] on",
		},
		{
			name:    "an annotated tag of someone else",
			version: "0.5.0-rc.1",
			tags:    []tag{{name: "v0.5.0-rc.1", tagger: "Owner", email: "owner@example.com"}},
			code:    1, stderr: "v0.5.0-rc.1 exists already",
		},
		{
			name:    "a lightweight tag on the commit",
			version: "0.5.0-rc.1",
			tags:    []tag{{name: "v0.5.0-rc.1"}},
			code:    1, stderr: "v0.5.0-rc.1 exists already",
		},
		{
			name:    "a release without its section in CHANGELOG.md",
			version: "0.6.0",
			tags:    []tag{{name: "v0.5.0", onFirstCommit: true}},
			code:    1,
			stderr:  "CHANGELOG.md has no release notes for 0.6.0",
		},
		{
			name:      "a pre-release with an empty Unreleased section",
			version:   "0.6.0-rc.1",
			tags:      []tag{{name: "v0.5.0", onFirstCommit: true}},
			changelog: "# Changelog\n\n## [Unreleased]\n\n## [0.5.0] - 2026-11-02\n\n- Final.\n",
			code:      1, stderr: "its section [Unreleased] is empty",
		},
		{
			name:     "ci-ok has not run",
			version:  "0.5.0-rc.1",
			noChecks: true,
			code:     1, stderr: "ci-ok has not run on",
		},
		{
			name:    "ci-ok failed",
			version: "0.5.0-rc.1",
			checks:  []checkRun{ciOK("github-actions", "completed", "failure")},
			code:    1, stderr: "ci-ok did not succeed on",
		},
		{
			name:    "ci-ok still runs",
			version: "0.5.0-rc.1",
			checks:  []checkRun{ciOK("github-actions", "in_progress", "")},
			code:    1, stderr: "github-actions in_progress none",
		},
		{
			name:    "ci-ok of another app",
			version: "0.5.0-rc.1",
			checks:  []checkRun{ciOK("someone-else", "completed", "success")},
			code:    1, stderr: "someone-else completed success",
		},
		{
			name:    "a second ci-ok that failed",
			version: "0.5.0-rc.1",
			checks:  []checkRun{ciOK("github-actions", "completed", "success"), ciOK("github-actions", "completed", "cancelled")},
			code:    1, stderr: "ci-ok did not succeed on",
		},
		{
			name:    "not on main",
			version: "0.5.0-rc.1",
			ref:     "refs/heads/feature",
			code:    1, stderr: "run on refs/heads/feature: tag releases from main only",
		},
		{
			name:    "a tag ref",
			version: "0.5.0-rc.1",
			ref:     "refs/tags/v0.4.0",
			code:    1, stderr: "tag releases from main only",
		},
		{
			name:    "a version with a v",
			version: "v0.5.0",
			code:    2, stderr: "v0.5.0 is not a release version: X.Y.Z, optionally with -alpha, -beta or -rc and .N, without the v",
		},
		{
			name:    "a version that is not a release's",
			version: "0.5.0-dev",
			code:    2, stderr: "0.5.0-dev is not a release version",
		},
		{
			name:    "two numbers",
			version: "0.5",
			code:    2, stderr: "0.5 is not a release version",
		},
		{
			name:    "the tags cannot be listed",
			version: "0.5.0-rc.1",
			fail:    [][2]string{{"matching-refs", "500"}},
			code:    1, stderr: "cannot list the tags of o-kolomoiets/Go-SFTP-Server",
		},
		{
			name:    "the check runs cannot be read",
			version: "0.5.0-rc.1",
			fail:    [][2]string{{"check-runs", "network"}},
			code:    1, stderr: "cannot read the check runs of",
		},
		{
			name:    "the tag object cannot be created",
			version: "0.5.0-rc.1",
			fail:    [][2]string{{"git/tags", "422"}},
			code:    1, stderr: "cannot create the tag object of v0.5.0-rc.1",
		},
		{
			name:    "the tag cannot be created",
			version: "0.5.0-rc.1",
			fail:    [][2]string{{"git/refs", "422"}},
			code:    1, stderr: "cannot create the tag v0.5.0-rc.1",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeGitHub(t)
			head := f.commits[1]
			for _, tg := range tt.tags {
				commit := head
				if tg.onFirstCommit {
					commit = f.commits[0]
				}
				switch {
				case tg.annotatedByBot:
					f.annotatedTag(tg.name, commit, botName, botEmail)
				case tg.tagger != "":
					f.annotatedTag(tg.name, commit, tg.tagger, tg.email)
				default:
					f.tag(tg.name, commit)
				}
			}
			switch {
			case tt.noChecks:
			case tt.checks != nil:
				f.checks(head, tt.checks...)
			default:
				f.checks(head, success...)
			}
			for _, fail := range tt.fail {
				f.failOn(fail[0], fail[1])
			}
			before := f.git("-C", f.repo, "for-each-ref", "refs/tags/")

			got := tagRelease(t, f, tt.changelog, tt.ref, tt.version)

			calls := f.calls()
			dispatch := "workflow run release.yml --ref v" + tt.version + " --repo " + fakeRepository
			if got.code != tt.code || !strings.Contains(got.stderr, tt.stderr) {
				t.Fatalf("tag-release.sh %s = exit %d\n%s\nstderr: %s\nwant exit %d, stderr with %q\ngh ran as:\n%s",
					tt.version, got.code, got.stdout, got.stderr, tt.code, tt.stderr, strings.Join(calls, "\n"))
			}
			created := slices.ContainsFunc(calls, func(c string) bool { return strings.Contains(c, "--method POST") })
			if tt.code != 0 {
				// Nothing is created or started, but for a failure in the
				// creation itself.
				if created && !strings.Contains(tt.stderr, "cannot create") {
					t.Errorf("a failed check created something:\n%s", strings.Join(calls, "\n"))
				}
				if slices.Contains(calls, dispatch) {
					t.Errorf("a failed run started release.yml")
				}
				if strings.Contains(tt.stderr, "cannot create") {
					return
				}
				if after := f.git("-C", f.repo, "for-each-ref", "refs/tags/"); after != before {
					t.Errorf("the tags changed:\n%s\nwere\n%s", after, before)
				}
				return
			}
			if !slices.Contains(calls, dispatch) || calls[len(calls)-1] != dispatch {
				t.Errorf("release.yml was not started last, with %q:\n%s", dispatch, strings.Join(calls, "\n"))
			}
			if tt.existing {
				if created {
					t.Errorf("a re-run created something:\n%s", strings.Join(calls, "\n"))
				}
				if !strings.Contains(got.stdout, "starting release.yml only") {
					t.Errorf("standard output: %q", got.stdout)
				}
			}
			checkBotTag(t, f, "v"+tt.version, head)
		})
	}
}

// tagRelease runs tag-release.sh VERSION in a directory with a
// CHANGELOG.md, on the second commit of f's repository.
func tagRelease(t *testing.T, f *fakeGitHub, changelog, ref, version string) result {
	t.Helper()
	dir := t.TempDir()
	if changelog == "" {
		changelog = tagChangelog
	}
	if err := os.WriteFile(filepath.Join(dir, "CHANGELOG.md"), []byte(changelog), 0o600); err != nil {
		t.Fatal(err)
	}
	if ref == "" {
		ref = "refs/heads/main"
	}
	env := []string{
		"GITHUB_REF=" + ref, "GITHUB_SHA=" + f.commits[1],
		"GITHUB_RUN_ID=42", "GITHUB_SERVER_URL=https://github.com",
	}
	return f.run(dir, "tag-release.sh", env, version)
}

// checkBotTag checks that tag is an annotated tag of github-actions[bot] on
// commit, as tag-release.sh creates it.
func checkBotTag(t *testing.T, f *fakeGitHub, tag, commit string) {
	t.Helper()
	if kind := strings.TrimSpace(f.git("-C", f.repo, "cat-file", "-t", "refs/tags/"+tag)); kind != "tag" {
		t.Fatalf("%s is a %s, not an annotated tag", tag, kind)
	}
	text := f.git("-C", f.repo, "cat-file", "tag", "refs/tags/"+tag)
	for _, want := range []string{
		"object " + commit + "\n", "type commit\n", "tag " + tag + "\n",
		"tagger " + botName + " <" + botEmail + "> ",
		"\n\ngosftpd " + tag + "\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the tag object of %s has no %q:\n%s", tag, want, text)
		}
	}
}

// TestTagReleaseRerun follows a run whose dispatch failed: the tag stays,
// and running the workflow again only starts release.yml.
func TestTagReleaseRerun(t *testing.T) {
	t.Parallel()
	f := newFakeGitHub(t)
	f.tag("v0.4.0", f.commits[0])
	f.checks(f.commits[1], ciOK("github-actions", "completed", "success"))
	f.failOn("workflow run", "422")
	got := tagRelease(t, f, "", "", "0.5.0-rc.1")
	if got.code != 1 || !strings.Contains(got.stderr, "cannot start release.yml on v0.5.0-rc.1: run this workflow again") {
		t.Fatalf("a failed dispatch: exit %d: %s", got.code, got.stderr)
	}
	checkBotTag(t, f, "v0.5.0-rc.1", f.commits[1])
	tagged := f.git("-C", f.repo, "rev-parse", "refs/tags/v0.5.0-rc.1")

	if err := os.Remove(filepath.Join(f.dir, "fail")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.dir, "log")); err != nil {
		t.Fatal(err)
	}
	got = tagRelease(t, f, "", "", "0.5.0-rc.1")
	if got.code != 0 || !strings.Contains(got.stdout, "v0.5.0-rc.1 exists on "+f.commits[1]+" from an earlier run; starting release.yml only") {
		t.Fatalf("the re-run: exit %d\n%s\nstderr: %s", got.code, got.stdout, got.stderr)
	}
	if again := f.git("-C", f.repo, "rev-parse", "refs/tags/v0.5.0-rc.1"); again != tagged {
		t.Errorf("the re-run changed the tag: %s, was %s", again, tagged)
	}
	want := []string{
		"api --paginate repos/" + fakeRepository + "/git/matching-refs/tags/v --jq .[].ref",
		"api repos/" + fakeRepository + "/git/ref/tags/v0.5.0-rc.1 --jq .object.type + \" \" + .object.sha",
		"api repos/" + fakeRepository + "/git/tags/" + strings.TrimSpace(tagged) +
			" --jq [.tag, .tagger.name, .tagger.email, .object.type, .object.sha] | join(\" \")",
		"api repos/" + fakeRepository + "/commits/" + f.commits[1] + "/check-runs?check_name=ci-ok&filter=latest" +
			" --jq .check_runs[] | [.app.slug, .status, .conclusion // \"none\"] | join(\" \")",
		"workflow run release.yml --ref v0.5.0-rc.1 --repo " + fakeRepository,
	}
	if calls := f.calls(); !slices.Equal(calls, want) {
		t.Errorf("gh ran as\n%s\nwant\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
}
