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
// The same goes for the DEV builds' default SECRET_KEY_BASE (keys_dev.go): a release
// binary has none, and refuses to start without SECRET_KEY_BASE.
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
	dev := build("server-dev", "-tags", "DEV")
	if !bytes.Contains(dev, []byte(path)) {
		t.Fatalf("a DEV binary doesn't contain %q: this test no longer detects the route", path)
	}
	devKey := []byte("duongondro DEV SECRET_KEY_BASE")
	if !bytes.Contains(dev, devKey) {
		t.Fatalf("a DEV binary doesn't contain its default key: this test no longer detects it")
	}
	release := build("server")
	if bytes.Contains(release, []byte(path)) {
		t.Fatalf("the release binary contains %q", path)
	}
	if bytes.Contains(release, devKey) {
		t.Fatal("the release binary contains the DEV builds' default SECRET_KEY_BASE")
	}

	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "server"), "serve")
	cmd.Dir = dir
	env := slices.DeleteFunc(os.Environ(), func(kv string) bool {
		return strings.HasPrefix(kv, "DATABASE_URL=") || strings.HasPrefix(kv, "LISTEN_ADDR=") ||
			strings.HasPrefix(kv, "RP_") || strings.HasPrefix(kv, "APPLE_") || strings.HasPrefix(kv, "APNS_") ||
			strings.HasPrefix(kv, "GOOGLE_") || strings.HasPrefix(kv, "FCM_") || strings.HasPrefix(kv, "MAIL_") ||
			strings.HasPrefix(kv, "AWS_") || strings.HasPrefix(kv, "SECRET_KEY_BASE")
	})
	env = append(env,
		"LISTEN_ADDR=127.0.0.1:"+port,
		"DATABASE_URL=postgres://nobody@127.0.0.1:1/unused",
		"RP_ID=localhost", "RP_ORIGINS=http://localhost:"+port,
	)

	// Without SECRET_KEY_BASE a release binary refuses to start, and migrate too.
	for _, command := range []string{"serve", "migrate"} {
		refused := exec.Command(filepath.Join(dir, "server"), command)
		refused.Dir, refused.Env = dir, env
		out, err := refused.CombinedOutput()
		if err == nil || !bytes.Contains(out, []byte("SECRET_KEY_BASE is not set")) {
			t.Fatalf("%s without SECRET_KEY_BASE: %v\n%s", command, err, out)
		}
	}

	cmd.Env = append(env, "SECRET_KEY_BASE=c2VjcmV0IGtleSBiYXNlIGZvciB0aGUgcmVsZWFzZSB0ZXN0LCA2NCBieXRlcyBsb25nIG9yIGFib3V0")
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
