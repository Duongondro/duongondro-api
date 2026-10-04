package server

import (
	"bufio"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// Every operation in api/openapi.yaml has a route, and every API route is
// in the contract: the handlers follow the file by hand, so this keeps the
// two from drifting apart.
func TestContractMatchesRoutes(t *testing.T) {
	f, err := os.Open("../../api/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pathLine := regexp.MustCompile(`^  (/\S*):\s*$`)
	opLine := regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
	sample := strings.NewReplacer(
		"{userId}", "0190f3a1-7b2c-7d4e-8f00-123456789abc",
		"{deviceId}", "0190f3a1-7b2c-7d4e-8f00-123456789abd",
		"{friendId}", "0190f3a1-7b2c-7d4e-8f00-123456789abe",
		"{logId}", "0190f3a1-7b2c-7d4e-8f00-123456789abf",
		"{inviteId}", "7K2MQ9XA",
		"{kind}", "1",
		"{practice}", "dorje-sempa",
	)
	mux := newServer(slog.New(slog.NewTextHandler(io.Discard, nil)), Deps{}).routes()
	documented := map[string]bool{}
	var path string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if m := pathLine.FindStringSubmatch(sc.Text()); m != nil {
			path = m[1]
			continue
		}
		m := opLine.FindStringSubmatch(sc.Text())
		if m == nil || path == "" {
			continue
		}
		method := strings.ToUpper(m[1])
		r := httptest.NewRequest(method, sample.Replace(path), nil)
		_, pattern := mux.Handler(r)
		if pattern == "/api/" || pattern == "/" {
			t.Errorf("%s %s is in the contract but not routed", method, path)
		}
		documented[method+" "+path] = true
	}
	if len(documented) < 35 {
		t.Fatalf("parsed only %d operations", len(documented))
	}
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+ /[^"]*)"`).FindAllSubmatch(src, -1)
	if len(routes) < 35 {
		t.Fatalf("found only %d routes in server.go", len(routes))
	}
	for _, m := range routes {
		if route := string(m[1]); !documented[route] {
			t.Errorf("%s is routed but not in api/openapi.yaml", route)
		}
	}
}
