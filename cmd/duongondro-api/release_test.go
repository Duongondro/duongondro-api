package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The dev sign-in (POST /api/dev/session, internal/server/dev_session_dev.go) signs
// anyone in without any sign-in method, so a release binary must not contain it at
// all. It is opt-in (-tags DEV), so this builds the binary plainly, checks that the
// route's path isn't in it, then runs it and checks that the route answers 404.
// Ported from CodeShare.
//
// Needs no database: the pool connects lazily, and a 404 never reaches it. Builds two
// binaries, so it's skipped with -short.
func TestReleaseBinaryHasNoDevSession(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the server twice")
	}
	const path = "/api/dev/session"
	dir := t.TempDir()
	build := func(name string, tags ...string) []byte {
		t.Helper()
		out := filepath.Join(dir, name)
		args := append([]string{"build"}, tags...)
		args = append(args, "-trimpath", "-ldflags=-s -w", "-o", out, ".")
		cmd := exec.Command("go", args...)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, output)
		}
		bin, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return bin
	}

	// With the tag the path is there, so not finding it below means something.
	if dev := build("server-dev", "-tags", "DEV"); !bytes.Contains(dev, []byte(path)) {
		t.Fatalf("a DEV binary doesn't contain %q: this test no longer detects the route", path)
	}
	if release := build("server"); bytes.Contains(release, []byte(path)) {
		t.Fatalf("the release binary contains %q", path)
	}

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "server"), "serve")
	cmd.Dir = dir
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "DATABASE_URL=") || strings.HasPrefix(kv, "LISTEN_ADDR=")
	})
	cmd.Env = append(env,
		"LISTEN_ADDR=127.0.0.1:"+port,
		"DATABASE_URL=postgres://nobody@127.0.0.1:1/unused",
	)
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	base := "http://127.0.0.1:" + port
	waitForHealth(t, base, &logs)
	resp, err := http.Post(base+path, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("POST %s on the release binary: status %d, want 404", path, resp.StatusCode)
	}
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}

func waitForHealth(t *testing.T, base string, logs *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if resp, err := http.Get(base + "/healthz"); err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("the release server didn't come up:\n%s", logs)
}
