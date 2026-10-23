// SPDX-License-Identifier: Apache-2.0

package release

import (
	"slices"
	"strings"
	"testing"
)

// TestReleaseGuard runs .github/scripts/release-guard.sh as release.yml's
// jobs do, against a fake gh whose tags come from a git repository.
func TestReleaseGuard(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		tags     []string       // lightweight tags on the first commit
		releases map[string]int // what releases/tags answers, 404 otherwise
		fail     [][2]string    // failOn arguments
		ref      string         // GITHUB_REF; GITHUB_REF_NAME is its last part
		refName  string         // GITHUB_REF_NAME, when not that
		code     int
		stderr   string // a part of standard error
	}{
		{
			name:     "the highest tag, whose release is not published",
			tags:     []string{"v0.1.0-alpha", "v0.4.0", "v0.5.0-rc.1", "vtest", "v1", "v0.6", "v9.0.0-dev", "v9.0.0.1"},
			releases: map[string]int{"v0.4.0": 200},
			ref:      "refs/tags/v0.5.0-rc.1",
		},
		{
			name: "a final on its rc's commit",
			tags: []string{"v0.4.0", "v0.5.0-rc.1", "v0.5.0"},
			ref:  "refs/tags/v0.5.0",
		},
		{
			name: "the rc of a final that exists",
			tags: []string{"v0.4.0", "v0.5.0-rc.1", "v0.5.0"},
			ref:  "refs/tags/v0.5.0-rc.1",
			code: 1, stderr: "v0.5.0-rc.1 is not the highest release tag of o-kolomoiets/Go-SFTP-Server: v0.5.0 is",
		},
		{
			name: "an older release",
			tags: []string{"v0.4.0", "v0.5.0-rc.1"},
			ref:  "refs/tags/v0.4.0",
			code: 1, stderr: "v0.4.0 is not the highest release tag of o-kolomoiets/Go-SFTP-Server: v0.5.0-rc.1 is",
		},
		{
			name: "numbers compare as numbers",
			tags: []string{"v0.9.0", "v0.10.0-rc.9", "v0.10.0-rc.10", "v0.10.0-rc"},
			ref:  "refs/tags/v0.10.0-rc.10",
		},
		{
			name: "rc.9 below rc.10",
			tags: []string{"v0.9.0", "v0.10.0-rc.9", "v0.10.0-rc.10"},
			ref:  "refs/tags/v0.10.0-rc.9",
			code: 1, stderr: "v0.10.0-rc.10 is",
		},
		{
			name: "alpha, beta, rc",
			tags: []string{"v1.0.0-alpha", "v1.0.0-alpha.1", "v1.0.0-beta", "v1.0.0-rc"},
			ref:  "refs/tags/v1.0.0-beta",
			code: 1, stderr: "v1.0.0-rc is",
		},
		{
			name: "a tag that is not a release's does not count",
			tags: []string{"v0.4.0", "v0.5.0-rc.1", "vtest", "v0.9.0-dev", "v1.0"},
			ref:  "refs/tags/v0.5.0-rc.1",
		},
		{
			name:     "a published release",
			tags:     []string{"v0.4.0", "v0.5.0"},
			releases: map[string]int{"v0.5.0": 200},
			ref:      "refs/tags/v0.5.0",
			code:     1, stderr: "v0.5.0 has a published release",
		},
		{
			name:     "an answer other than 404 fails",
			tags:     []string{"v0.5.0"},
			releases: map[string]int{"v0.5.0": 403},
			ref:      "refs/tags/v0.5.0",
			code:     1, stderr: "cannot tell whether v0.5.0 has a published release (403): gh: Forbidden (HTTP 403)",
		},
		{
			name: "a server error from releases/tags",
			tags: []string{"v0.5.0"},
			fail: [][2]string{{"releases/tags", "500"}},
			ref:  "refs/tags/v0.5.0",
			code: 1, stderr: "cannot tell whether v0.5.0 has a published release (500)",
		},
		{
			name: "no answer from releases/tags",
			tags: []string{"v0.5.0"},
			fail: [][2]string{{"releases/tags", "network"}},
			ref:  "refs/tags/v0.5.0",
			code: 1, stderr: "cannot tell whether v0.5.0 has a published release (no answer): error connecting to api.github.com",
		},
		{
			name: "the tags cannot be listed",
			tags: []string{"v0.5.0"},
			fail: [][2]string{{"matching-refs", "500"}},
			ref:  "refs/tags/v0.5.0",
			code: 1, stderr: "cannot list the tags of o-kolomoiets/Go-SFTP-Server",
		},
		{
			name: "no answer for the tags",
			tags: []string{"v0.5.0"},
			fail: [][2]string{{"matching-refs", "network"}},
			ref:  "refs/tags/v0.5.0",
			code: 1, stderr: "cannot list the tags",
		},
		{
			name: "a tag that does not exist",
			tags: []string{"v0.4.0"},
			ref:  "refs/tags/v0.5.0",
			code: 1, stderr: "o-kolomoiets/Go-SFTP-Server has no tag v0.5.0",
		},
		{
			name: "a branch",
			tags: []string{"v0.4.0"},
			ref:  "refs/heads/main",
			code: 1, stderr: "refs/heads/main is not a release tag",
		},
		{
			name: "a tag that is not a release's",
			tags: []string{"v0.4.0", "v0.5.0-dev"},
			ref:  "refs/tags/v0.5.0-dev",
			code: 1, stderr: "refs/tags/v0.5.0-dev is not a release tag",
		},
		{
			name: "a tag without the v",
			tags: []string{"0.5.0"},
			ref:  "refs/tags/0.5.0",
			code: 1, stderr: "is not a release tag",
		},
		{
			name:    "GITHUB_REF_NAME not the tag of GITHUB_REF",
			tags:    []string{"v0.4.0", "v0.5.0"},
			ref:     "refs/tags/v0.5.0",
			refName: "v0.4.0",
			code:    1, stderr: "GITHUB_REF_NAME v0.4.0 is not the tag of refs/tags/v0.5.0",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newFakeGitHub(t)
			for _, tag := range tt.tags {
				f.tag(tag, f.commits[0])
			}
			for tag, status := range tt.releases {
				f.release(tag, status)
			}
			for _, fail := range tt.fail {
				f.failOn(fail[0], fail[1])
			}
			name := tt.refName
			if name == "" {
				name = tt.ref[strings.LastIndex(tt.ref, "/")+1:]
			}
			got := f.run(t.TempDir(), "release-guard.sh", []string{"GITHUB_REF=" + tt.ref, "GITHUB_REF_NAME=" + name})
			if got.code != tt.code || !strings.Contains(got.stderr, tt.stderr) {
				t.Errorf("release-guard.sh on %s = exit %d\n%s\nstderr: %s\nwant exit %d, stderr with %q",
					tt.ref, got.code, got.stdout, got.stderr, tt.code, tt.stderr)
			}
			if tt.code == 0 && !strings.Contains(got.stdout, name+" is the highest release tag of "+fakeRepository+" and has no published release") {
				t.Errorf("standard output: %q", got.stdout)
			}
		})
	}
}

// TestReleaseGuardCalls checks the requests the guard makes: the tag list
// and the release of the tag, nothing that writes.
func TestReleaseGuardCalls(t *testing.T) {
	t.Parallel()
	f := newFakeGitHub(t)
	f.tag("v0.4.0", f.commits[0])
	f.annotatedTag("v0.5.0-rc.1", f.commits[1], "github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com")
	got := f.run(t.TempDir(), "release-guard.sh", []string{"GITHUB_REF=refs/tags/v0.5.0-rc.1", "GITHUB_REF_NAME=v0.5.0-rc.1"})
	if got.code != 0 {
		t.Fatalf("exit %d: %s", got.code, got.stderr)
	}
	want := []string{
		"api --paginate repos/" + fakeRepository + "/git/matching-refs/tags/v --jq .[].ref",
		"api --include repos/" + fakeRepository + "/releases/tags/v0.5.0-rc.1",
	}
	if calls := f.calls(); !slices.Equal(calls, want) {
		t.Errorf("gh ran as\n%s\nwant\n%s", strings.Join(calls, "\n"), strings.Join(want, "\n"))
	}
}

// TestReleaseOrder checks the order of release-tags.sh, which tag.yml and
// the guard share, against the order of semantic versions.
func TestReleaseOrder(t *testing.T) {
	t.Parallel()
	want := []string{
		"v0.1.0-alpha", "v0.4.0", "v0.5.0-alpha", "v0.5.0-alpha.1", "v0.5.0-alpha.2", "v0.5.0-beta",
		"v0.5.0-beta.10", "v0.5.0-rc", "v0.5.0-rc.0", "v0.5.0-rc.1", "v0.5.0-rc.2", "v0.5.0-rc.9",
		"v0.5.0-rc.10", "v0.5.0", "v0.5.1-rc.1", "v0.5.1", "v0.9.0", "v0.10.0", "v1.0.0-rc.1", "v1.0.0",
		"v1.1.0", "v2.0.0", "v10.0.0",
	}
	f := newFakeGitHub(t)
	for i, tag := range want {
		f.tag(tag, f.commits[i%2])
	}
	f.tag("vtest", f.commits[0])
	f.tag("v11.0.0-dev", f.commits[0])
	got := f.shell(`. "$SCRIPTS/release-tags.sh" && release_tags`)
	if got.code != 0 || got.stdout != strings.Join(want, "\n")+"\n" {
		t.Errorf("release_tags = exit %d (%s)\n%s\nwant\n%s", got.code, got.stderr, got.stdout, strings.Join(want, "\n"))
	}
	// Shuffled input, as release_order gets it from tag-release.sh.
	shuffled := slices.Clone(want)
	for i := range shuffled {
		j := (i*7 + 3) % len(shuffled)
		shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
	}
	got = f.bash(t.TempDir(), []string{"SCRIPTS=" + scripts(t)},
		append([]string{"-c", `. "$SCRIPTS/release-tags.sh" && printf '%s\n' "$@" | release_order`, "bash"}, shuffled...)...)
	if got.code != 0 || got.stdout != strings.Join(want, "\n")+"\n" {
		t.Errorf("release_order of %q = exit %d (%s)\n%s", shuffled, got.code, got.stderr, got.stdout)
	}
}
