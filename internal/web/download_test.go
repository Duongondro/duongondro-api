package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

type fakeDownloads struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
}

func (f *fakeDownloads) Count(_ context.Context, platform string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.counts == nil {
		f.counts = map[string]int64{}
	}
	f.counts[platform]++
	return nil
}

func (f *fakeDownloads) Total(_ context.Context, platform string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[platform], f.err
}

const apk = "https://github.com/Duongondro/duongondro-android/releases/latest/download/duongondro.apk"

func download(t *testing.T, h http.Handler, method, target, ua string, header ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	req.Header.Set("User-Agent", ua)
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

const phone = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Mobile Safari/537.36"

// The link only redirects to the newest APK, uncached, and never counts, so a
// link preview or a crawler following a shared link changes nothing.
func TestDownloadRedirectsWithoutCounting(t *testing.T) {
	d := &fakeDownloads{}
	h := Handler(d)
	for _, tc := range []struct{ method, path, ua string }{
		{http.MethodGet, "/download/android", phone},
		{http.MethodGet, "/download/android/", "curl/8.7.1"},
		{http.MethodHead, "/download/android", phone},
		{http.MethodGet, "/download/android", "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"},
	} {
		rec := download(t, h, tc.method, tc.path, tc.ua)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != apk {
			t.Errorf("%s %s: %d %q", tc.method, tc.path, rec.Code, rec.Header().Get("Location"))
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s %s: Cache-Control = %q", tc.method, tc.path, got)
		}
		checkSecurityHeaders(t, rec)
	}
	if got, _ := d.Total(t.Context(), "android"); got != 0 {
		t.Errorf("following the link counted %d downloads", got)
	}
	if rec := download(t, h, http.MethodPost, "/download/android", phone); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
		t.Errorf("POST to the link: %d %q", rec.Code, rec.Header().Get("Allow"))
	}
}

// The beacon counts a click from the site itself, not one from another site's
// page and not a crawler's, and always answers 204, uncached.
func TestDownloadBeacon(t *testing.T) {
	d := &fakeDownloads{}
	h := Handler(d)
	cases := []struct {
		ua      string
		header  []string
		counted bool
	}{
		{phone, []string{"Sec-Fetch-Site", "same-origin"}, true},
		{"curl/8.7.1", nil, true},
		{"Mozilla/5.0 (Linux; Android 9; CUBOT P30) Chrome/120.0 Mobile", nil, true},
		{phone, []string{"Sec-Fetch-Site", "cross-site"}, false},
		{phone, []string{"Sec-Fetch-Site", "same-site"}, false},
		{"Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)", nil, false},
		{"TelegramBot (like TwitterBot)", nil, false},
		{"WhatsApp/2.23.20.0 A", nil, false},
		{"facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)", nil, false},
		{"Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)", nil, false},
		{"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", nil, false},
	}
	var want int64
	for _, tc := range cases {
		rec := download(t, h, http.MethodPost, "/download/android/count", tc.ua, tc.header...)
		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Errorf("%s %v: %d %q", tc.ua, tc.header, rec.Code, rec.Body)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s: Cache-Control = %q", tc.ua, got)
		}
		checkSecurityHeaders(t, rec)
		if tc.counted {
			want++
		}
		if got, _ := d.Total(t.Context(), "android"); got != want {
			t.Errorf("%s %v: total %d, want %d", tc.ua, tc.header, got, want)
			want = got
		}
	}
	for _, m := range []string{http.MethodPut, http.MethodDelete, http.MethodPatch} {
		if rec := download(t, h, m, "/download/android/count", phone); rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD, POST" {
			t.Errorf("%s count: %d %q", m, rec.Code, rec.Header().Get("Allow"))
		}
	}
	if rec := download(t, h, http.MethodPost, "/download/ios/count", phone); rec.Code != http.StatusNotFound {
		t.Errorf("unknown platform: %d", rec.Code)
	}
}

// A database that cannot count still answers the beacon, and never touches the link.
func TestDownloadBeaconWhenCountingFails(t *testing.T) {
	rec := download(t, Handler(&fakeDownloads{err: errors.New("down")}), http.MethodPost, "/download/android/count", phone)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("%d", rec.Code)
	}
}

func TestDownloadCount(t *testing.T) {
	d := &fakeDownloads{counts: map[string]int64{"android": 1234}}
	h := Handler(d)
	rec := download(t, h, http.MethodGet, "/download/android/count", phone)
	if rec.Code != http.StatusOK || rec.Body.String() != "{\"count\":1234}\n" {
		t.Fatalf("count: %d %q", rec.Code, rec.Body)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=60" {
		t.Errorf("Cache-Control = %q", cc)
	}
	checkSecurityHeaders(t, rec)
	if rec := download(t, h, http.MethodHead, "/download/android/count", phone); rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD count: %d, %d bytes", rec.Code, rec.Body.Len())
	}
	if got, _ := d.Total(t.Context(), "android"); got != 1234 {
		t.Errorf("reading the count changed it to %d", got)
	}

	d.err = errors.New("down")
	rec = download(t, h, http.MethodGet, "/download/android/count", phone)
	if rec.Code != http.StatusInternalServerError || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("count without a database: %d %q", rec.Code, rec.Header().Get("Cache-Control"))
	}
}
