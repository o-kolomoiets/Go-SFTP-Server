// SPDX-License-Identifier: Apache-2.0

package release

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The scripts of release.yml and tag.yml talk to GitHub only through gh.
// In these tests gh is this test binary, started through a wrapper script
// with GOSFTPD_FAKE_GH naming a state directory: a git repository whose
// tags stand for the repository's, the answers of releases/tags and of the
// check runs, and failures to inject. It answers like gh 2.89.0 against the
// REST API: JSON bodies, --jq through jq -r, --include with the status
// line, and for an HTTP error the body on standard output, "gh: MESSAGE
// (HTTP STATUS)" on standard error and exit status 1. Every call is logged.

// fakeRepository is the repository the scripts are run for.
const fakeRepository = "o-kolomoiets/Go-SFTP-Server"

func TestMain(m *testing.M) {
	if dir := os.Getenv("GOSFTPD_FAKE_GH"); dir != "" {
		os.Exit(fakeGH(dir, os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(m.Run())
}

// fakeGitHub is the state behind the fake gh.
type fakeGitHub struct {
	t       *testing.T
	dir     string // the state directory
	repo    string // the git repository behind git/refs and git/tags
	bin     string // the directory of the gh wrapper
	commits []string
}

// checkRun is a check run as the check-runs endpoint returns it.
type checkRun struct {
	Name       string  `json:"name"`
	Status     string  `json:"status"`
	Conclusion *string `json:"conclusion"`
	App        struct {
		Slug string `json:"slug"`
	} `json:"app"`
}

// newFakeGitHub creates the state of a fake gh with a repository of two
// commits, and the wrapper that runs this test binary as gh.
func newFakeGitHub(t *testing.T) *fakeGitHub {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the release workflows run the scripts on Linux (GNU sort -V)")
	}
	for _, tool := range []string{"git", "jq"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not installed", tool)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeGitHub{t: t, dir: t.TempDir(), bin: t.TempDir()}
	f.repo = filepath.Join(f.dir, "repo")
	wrapper := "#!/bin/sh\nexec '" + exe + "' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(f.bin, "gh"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	f.git("init", "-q", "-b", "main", f.repo)
	for i := range 2 {
		f.git("-C", f.repo, "commit", "-q", "--allow-empty", "-m", "commit "+strconv.Itoa(i))
		f.commits = append(f.commits, strings.TrimSpace(f.git("-C", f.repo, "rev-parse", "HEAD")))
	}
	return f
}

// git runs git with a fixed identity and no configuration of the user's.
func (f *fakeGitHub) git(args ...string) string {
	f.t.Helper()
	cmd := exec.CommandContext(f.t.Context(), "git", args...)
	cmd.Env = append(os.Environ(), gitEnv("gosftpd test", "test@example.com")...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// gitEnv is the environment for git with this identity and without the
// user's and the system's configuration.
func gitEnv(name, email string) []string {
	return []string{
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=" + name, "GIT_AUTHOR_EMAIL=" + email,
		"GIT_COMMITTER_NAME=" + name, "GIT_COMMITTER_EMAIL=" + email,
	}
}

// tag creates a lightweight tag.
func (f *fakeGitHub) tag(name, commit string) {
	f.t.Helper()
	f.git("-C", f.repo, "tag", name, commit)
}

// annotatedTag creates an annotated tag with this tagger.
func (f *fakeGitHub) annotatedTag(name, commit, tagger, email string) {
	f.t.Helper()
	cmd := exec.CommandContext(f.t.Context(), "git", "-C", f.repo, "tag", "-a", "-m", "gosftpd "+name, name, commit)
	cmd.Env = append(os.Environ(), gitEnv(tagger, email)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		f.t.Fatalf("git tag -a %s: %v\n%s", name, err, out)
	}
}

// release sets the status that releases/tags/TAG answers: 404 unless set.
func (f *fakeGitHub) release(tag string, status int) {
	f.t.Helper()
	f.appendLine("releases", tag+" "+strconv.Itoa(status))
}

// failOn makes every call whose endpoint (or "workflow run") contains
// part fail: with this HTTP status, or "network" for no answer at all.
func (f *fakeGitHub) failOn(part, status string) {
	f.t.Helper()
	f.appendLine("fail", part+" "+status)
}

func (f *fakeGitHub) appendLine(name, line string) {
	f.t.Helper()
	file, err := os.OpenFile(filepath.Join(f.dir, name), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		f.t.Fatal(err)
	}
	defer file.Close()
	if _, err := fmt.Fprintln(file, line); err != nil {
		f.t.Fatal(err)
	}
}

// calls returns the gh command lines run so far.
func (f *fakeGitHub) calls() []string {
	f.t.Helper()
	data, err := os.ReadFile(filepath.Join(f.dir, "log"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

// result is what a run of a script gave.
type result struct {
	stdout, stderr string
	code           int
}

// run runs a script of .github/scripts with bash in dir, with gh the fake,
// GITHUB_REPOSITORY set and env added; nothing else of this process's
// environment but PATH reaches it.
func (f *fakeGitHub) run(dir, script string, env []string, args ...string) result {
	f.t.Helper()
	return f.bash(dir, env, append([]string{filepath.Join(scripts(f.t), script)}, args...)...)
}

// shell runs a bash command in that environment, with SCRIPTS naming
// .github/scripts.
func (f *fakeGitHub) shell(command string) result {
	f.t.Helper()
	return f.bash(f.t.TempDir(), []string{"SCRIPTS=" + scripts(f.t)}, "-c", command)
}

// scripts returns the absolute path of .github/scripts.
func scripts(t *testing.T) string {
	t.Helper()
	path, err := filepath.Abs(filepath.Join(root, ".github", "scripts"))
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *fakeGitHub) bash(dir string, env []string, args ...string) result {
	f.t.Helper()
	cmd := exec.CommandContext(f.t.Context(), "bash", args...)
	cmd.Dir = dir
	cmd.Env = append([]string{
		"PATH=" + f.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"HOME=" + f.t.TempDir(),
		"GOSFTPD_FAKE_GH=" + f.dir,
		"GH_TOKEN=fake",
		"GITHUB_REPOSITORY=" + fakeRepository,
	}, env...)
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	var r result
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	default:
		f.t.Fatal(err)
	}
	r.stdout, r.stderr = out.String(), errOut.String()
	return r
}

// fakeGH is the fake gh: it runs args against the state in dir and returns
// the exit status.
func fakeGH(dir string, args []string, stdout, stderr io.Writer) int {
	if err := logCall(dir, args); err != nil {
		fmt.Fprintln(stderr, "fake gh:", err)
		return 2
	}
	switch {
	case len(args) > 0 && args[0] == "api":
		return fakeAPI(dir, args[1:], stdout, stderr)
	case len(args) > 1 && args[0] == "workflow" && args[1] == "run":
		if status, ok := injectedFailure(dir, "workflow run"); ok {
			if status == "network" {
				fmt.Fprintln(stderr, "error connecting to api.github.com")
			} else {
				fmt.Fprintf(stderr, "could not create workflow dispatch event: HTTP %s\n", status)
			}
			return 1
		}
		fmt.Fprintf(stderr, "✓ Created workflow_dispatch event for %s\n", args[2])
		return 0
	}
	fmt.Fprintf(stderr, "fake gh: unsupported command %q\n", args)
	return 2
}

func logCall(dir string, args []string) error {
	file, err := os.OpenFile(filepath.Join(dir, "log"), os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintln(file, strings.Join(args, " "))
	return err
}

// injectedFailure returns the failure set with failOn for a call.
func injectedFailure(dir, call string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(dir, "fail"))
	if err != nil {
		return "", false
	}
	for line := range strings.Lines(string(data)) {
		part, status, _ := strings.Cut(strings.TrimSpace(line), " ")
		if strings.Contains(call, part) {
			return status, true
		}
	}
	return "", false
}

// apiRequest is a parsed gh api command line.
type apiRequest struct {
	method, endpoint, jq string
	include, silent      bool
	fields               map[string]string
}

func parseAPI(args []string) (apiRequest, error) {
	r := apiRequest{fields: map[string]string{}}
	for i := 0; i < len(args); i++ {
		a := args[i]
		value := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--paginate": // one page
		case "--include", "-i":
			r.include = true
		case "--silent":
			r.silent = true
		case "--jq", "-q":
			r.jq, err = value()
		case "--method", "-X":
			r.method, err = value()
		case "-f", "--raw-field", "-F", "--field":
			var field string
			field, err = value()
			k, v, ok := strings.Cut(field, "=")
			if !ok {
				err = fmt.Errorf("field %q has no =", field)
			}
			r.fields[k] = v
		default:
			if strings.HasPrefix(a, "-") || r.endpoint != "" {
				return r, fmt.Errorf("unsupported argument %q", a)
			}
			r.endpoint = a
		}
		if err != nil {
			return r, err
		}
	}
	if r.method == "" {
		r.method = "GET"
		if len(r.fields) > 0 {
			r.method = "POST"
		}
	}
	return r, nil
}

func fakeAPI(dir string, args []string, stdout, stderr io.Writer) int {
	req, err := parseAPI(args)
	if err != nil {
		fmt.Fprintln(stderr, "fake gh:", err)
		return 2
	}
	if status, ok := injectedFailure(dir, req.endpoint); ok {
		if status == "network" {
			fmt.Fprintln(stderr, "error connecting to api.github.com")
			return 1
		}
		code, err := strconv.Atoi(status)
		if err != nil {
			fmt.Fprintln(stderr, "fake gh: bad status", status)
			return 2
		}
		return reply(req, code, map[string]string{"message": "Injected"}, stdout, stderr)
	}
	status, body := route(dir, req)
	return reply(req, status, body, stdout, stderr)
}

// reply writes an answer as gh does.
func reply(req apiRequest, status int, body any, stdout, stderr io.Writer) int {
	data, err := json.Marshal(body)
	if err != nil {
		fmt.Fprintln(stderr, "fake gh:", err)
		return 2
	}
	if req.include {
		fmt.Fprintf(stdout, "HTTP/1.1 %d %s\nContent-Type: application/json; charset=utf-8\r\n\r\n", status, statusText(status))
	}
	if status >= 400 {
		fmt.Fprintf(stdout, "%s", data)
		message := "Error"
		if m, ok := body.(map[string]string); ok && m["message"] != "" {
			message = m["message"]
		}
		fmt.Fprintf(stderr, "gh: %s (HTTP %d)\n", message, status)
		return 1
	}
	if req.silent {
		return 0
	}
	if req.jq == "" {
		fmt.Fprintf(stdout, "%s", data)
		return 0
	}
	cmd := exec.CommandContext(context.Background(), "jq", "-r", req.jq)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = bytes.NewReader(data), stdout, stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintln(stderr, "fake gh: jq:", err)
		return 1
	}
	return 0
}

func statusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 201:
		return "Created"
	case 403:
		return "Forbidden"
	case 404:
		return "Not Found"
	case 422:
		return "Unprocessable Entity"
	case 500:
		return "Internal Server Error"
	}
	return "Status"
}

var notFound = map[string]string{"message": "Not Found"}

// route answers a request from the state in dir.
func route(dir string, req apiRequest) (int, any) {
	repo := filepath.Join(dir, "repo")
	u, err := url.Parse(req.endpoint)
	if err != nil {
		return 400, map[string]string{"message": err.Error()}
	}
	path, ok := strings.CutPrefix(u.Path, "repos/"+fakeRepository+"/")
	if !ok {
		return 404, notFound
	}
	gitIn := func(stdin string, args ...string) (string, error) {
		cmd := exec.CommandContext(context.Background(), "git", append([]string{"-C", repo}, args...)...)
		cmd.Env = append(os.Environ(), gitEnv("fake", "fake@example.com")...)
		cmd.Stdin = strings.NewReader(stdin)
		out, err := cmd.Output()
		return strings.TrimSpace(string(out)), err
	}
	git := func(args ...string) (string, error) { return gitIn("", args...) }
	object := func(sha string) map[string]string {
		kind, _ := git("cat-file", "-t", sha)
		return map[string]string{"sha": sha, "type": kind}
	}
	switch {
	case req.method == "GET" && path == "git/matching-refs/tags/v":
		out, err := git("for-each-ref", "--format=%(refname) %(objectname)", "refs/tags/")
		if err != nil {
			return 500, map[string]string{"message": err.Error()}
		}
		refs := []map[string]any{}
		for line := range strings.Lines(out) {
			name, sha, _ := strings.Cut(strings.TrimSpace(line), " ")
			if strings.HasPrefix(name, "refs/tags/v") {
				refs = append(refs, map[string]any{"ref": name, "object": object(sha)})
			}
		}
		return 200, refs
	case req.method == "GET" && strings.HasPrefix(path, "git/ref/tags/"):
		ref := "refs/tags/" + strings.TrimPrefix(path, "git/ref/tags/")
		sha, err := git("rev-parse", "--verify", "--quiet", ref)
		if err != nil {
			return 404, notFound
		}
		return 200, map[string]any{"ref": ref, "object": object(sha)}
	case req.method == "GET" && strings.HasPrefix(path, "git/tags/"):
		sha := strings.TrimPrefix(path, "git/tags/")
		if kind, _ := git("cat-file", "-t", sha); kind != "tag" {
			return 404, notFound
		}
		text, err := git("cat-file", "tag", sha)
		if err != nil {
			return 500, map[string]string{"message": err.Error()}
		}
		return 200, parseTag(sha, text)
	case req.method == "GET" && strings.HasPrefix(path, "releases/tags/"):
		tag := strings.TrimPrefix(path, "releases/tags/")
		data, _ := os.ReadFile(filepath.Join(dir, "releases"))
		status := 404
		for line := range strings.Lines(string(data)) {
			if t, s, _ := strings.Cut(strings.TrimSpace(line), " "); t == tag {
				status, _ = strconv.Atoi(s)
			}
		}
		if status == 200 {
			return 200, map[string]any{"tag_name": tag, "draft": false}
		}
		return status, map[string]string{"message": statusText(status)}
	case req.method == "GET" && strings.HasPrefix(path, "commits/") && strings.HasSuffix(path, "/check-runs"):
		sha := strings.TrimSuffix(strings.TrimPrefix(path, "commits/"), "/check-runs")
		var runs []checkRun
		if data, err := os.ReadFile(filepath.Join(dir, "checks-"+sha+".json")); err == nil {
			if err := json.Unmarshal(data, &runs); err != nil {
				return 500, map[string]string{"message": err.Error()}
			}
		}
		selected := []checkRun{}
		for _, r := range runs {
			if name := u.Query().Get("check_name"); name == "" || r.Name == name {
				selected = append(selected, r)
			}
		}
		return 200, map[string]any{"total_count": len(selected), "check_runs": selected}
	case req.method == "POST" && path == "git/tags":
		return createTag(req.fields, gitIn)
	case req.method == "POST" && path == "git/refs":
		ref, sha := req.fields["ref"], req.fields["sha"]
		if !strings.HasPrefix(ref, "refs/") || sha == "" {
			return 422, map[string]string{"message": "Invalid request"}
		}
		if _, err := git("rev-parse", "--verify", "--quiet", ref); err == nil {
			return 422, map[string]string{"message": "Reference already exists"}
		}
		if _, err := git("update-ref", ref, sha, ""); err != nil {
			return 422, map[string]string{"message": "Object does not exist"}
		}
		return 201, map[string]any{"ref": ref, "object": object(sha)}
	}
	return 404, map[string]string{"message": "Not Found (fake gh)"}
}

// createTag creates a tag object, as POST git/tags does: it is reachable
// only once a ref names it.
func createTag(fields map[string]string, git func(stdin string, args ...string) (string, error)) (int, any) {
	for _, k := range []string{"tag", "message", "object", "type", "tagger[name]", "tagger[email]"} {
		if fields[k] == "" {
			return 422, map[string]string{"message": "Invalid request: no " + k}
		}
	}
	text := fmt.Sprintf("object %s\ntype %s\ntag %s\ntagger %s <%s> %d +0000\n\n%s\n",
		fields["object"], fields["type"], fields["tag"], fields["tagger[name]"], fields["tagger[email]"],
		time.Now().Unix(), fields["message"])
	sha, err := git(text, "mktag")
	if err != nil {
		return 422, map[string]string{"message": "Object does not exist"}
	}
	got, _ := git("", "cat-file", "tag", sha)
	return 201, parseTag(sha, got)
}

// parseTag turns the text of a tag object into the JSON of git/tags.
func parseTag(sha, text string) map[string]any {
	tag := map[string]any{"sha": sha}
	header, message, _ := strings.Cut(text, "\n\n")
	tag["message"] = message
	object := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(header))
	for scanner.Scan() {
		key, value, _ := strings.Cut(scanner.Text(), " ")
		switch key {
		case "object":
			object["sha"] = value
		case "type":
			object["type"] = value
		case "tag":
			tag["tag"] = value
		case "tagger":
			name, rest, _ := strings.Cut(value, " <")
			email, _, _ := strings.Cut(rest, ">")
			tag["tagger"] = map[string]string{"name": name, "email": email}
		}
	}
	tag["object"] = object
	return tag
}
