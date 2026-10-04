package server

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

// WellKnown configures the association files the apex domain serves, which let
// invite, friend and magic links open the apps (Universal Links, App Links) and let
// passkeys use duongondro.app as their relying party. Apple's and Google's verifiers
// reject redirects, so Caddy routes the apex's /.well-known/ here directly.
type WellKnown struct {
	// AppleAppIDs are <team id>.<bundle id>.
	AppleAppIDs []string
	// AndroidPackage and the SHA-256 fingerprints of its signing certificates.
	AndroidPackage      string
	AndroidFingerprints []string
}

// Link paths: invites (/I/), friend codes (/F/), magic links (/m/). The QR codes are
// upper-case to stay in alphanumeric mode (design: Social › Codes), so both cases.
var appLinkPaths = []string{"/I/*", "/i/*", "/F/*", "/f/*", "/m/*"}

func registerWellKnown(e *echo.Echo, w WellKnown) {
	if len(w.AppleAppIDs) > 0 {
		aasa := map[string]any{
			"applinks": map[string]any{"details": []map[string]any{{
				"appIDs": w.AppleAppIDs,
				"components": func() []map[string]string {
					out := make([]map[string]string, len(appLinkPaths))
					for i, p := range appLinkPaths {
						out[i] = map[string]string{"/": p}
					}
					return out
				}(),
			}}},
			"webcredentials": map[string]any{"apps": w.AppleAppIDs},
		}
		e.GET("/.well-known/apple-app-site-association", func(c *echo.Context) error {
			return c.JSON(http.StatusOK, aasa)
		})
	}
	if w.AndroidPackage != "" && len(w.AndroidFingerprints) > 0 {
		links := []map[string]any{{
			"relation": []string{"delegate_permission/common.handle_all_urls", "delegate_permission/common.get_login_creds"},
			"target": map[string]any{"namespace": "android_app", "package_name": w.AndroidPackage,
				"sha256_cert_fingerprints": w.AndroidFingerprints},
		}}
		e.GET("/.well-known/assetlinks.json", func(c *echo.Context) error {
			return c.JSON(http.StatusOK, links)
		})
	}
}
