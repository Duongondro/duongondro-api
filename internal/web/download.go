package web

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
)

// Downloads keeps one running total per platform. It stores nothing about who
// downloaded: no address, no user agent, no time finer than the day.
type Downloads interface {
	Count(ctx context.Context, platform string) error
	Total(ctx context.Context, platform string) (int64, error)
}

// downloadURLs are where /download/<platform> sends the browser: the stable
// URL of the newest release's file.
var downloadURLs = map[string]string{
	"android": "https://github.com/Duongondro/duongondro-android/releases/latest/download/duongondro.apk",
}

// cacheCount lets browsers and Caddy reuse the total for a minute, so a busy
// landing page does not query the database on every view.
const cacheCount = "public, max-age=60"

// serveDownload answers the download links:
//
//   - GET /download/<platform>: 302 to the file, uncached. It never counts, so
//     a link preview or a crawler following a shared link changes nothing.
//   - POST /download/<platform>/count: counts one download and answers 204. The
//     landing page's script sends it as a beacon when someone clicks the button.
//     The server limits it per client address (internal/server).
//   - GET /download/<platform>/count: {"count": N}, cached for a minute.
func (h handler) serveDownload(w http.ResponseWriter, r *http.Request, rest string) {
	platform, sub, _ := strings.Cut(strings.TrimSuffix(rest, "/"), "/")
	target, ok := downloadURLs[platform]
	if !ok || (sub != "" && sub != "count") {
		http.NotFound(w, r)
		return
	}
	hd := w.Header()
	switch {
	case sub == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		hd.Set("Cache-Control", cacheNone)
		hd.Set("Pragma", "no-cache")
		http.Redirect(w, r, target, http.StatusFound)
	case sub == "count" && r.Method == http.MethodPost:
		hd.Set("Cache-Control", cacheNone)
		if counts(r) {
			// The download itself never depends on this, so a failure is only logged.
			if err := h.downloads.Count(r.Context(), platform); err != nil {
				slog.WarnContext(r.Context(), "download not counted", "platform", platform, "error", err.Error())
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case sub == "count" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		n, err := h.downloads.Total(r.Context(), platform)
		if err != nil {
			slog.ErrorContext(r.Context(), "download total", "platform", platform, "error", err.Error())
			hd.Set("Cache-Control", cacheNone)
			http.Error(w, "unavailable", http.StatusInternalServerError)
			return
		}
		hd.Set("Cache-Control", cacheCount)
		hd.Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			_, _ = w.Write([]byte(`{"count":` + strconv.FormatInt(n, 10) + "}\n"))
		}
	default:
		if sub == "count" {
			hd.Set("Allow", "GET, HEAD, POST")
		} else {
			hd.Set("Allow", "GET, HEAD")
		}
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// counts says whether a count beacon looks like a person's click on the landing
// page: sent from the site itself (browsers mark a beacon from another site's
// page as cross-site) and not by a crawler.
func counts(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	return !isBot(r.UserAgent())
}

// botMarks are lower-case substrings of crawler and link-preview user agents.
// "bot" covers Googlebot, bingbot, Applebot, Slackbot, TelegramBot, Discordbot,
// Twitterbot, LinkedInBot and the like.
var botMarks = []string{
	"bot", "crawl", "spider", "facebookexternalhit", "meta-externalagent", "whatsapp",
	"slack-imgproxy", "embedly", "preview",
}

func isBot(ua string) bool {
	ua = strings.ToLower(ua)
	// Cubot is an Android phone maker ("Android 9; CUBOT P30"), not a crawler.
	ua = strings.ReplaceAll(ua, "cubot", "")
	for _, m := range botMarks {
		if strings.Contains(ua, m) {
			return true
		}
	}
	return false
}
