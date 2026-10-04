//go:build !DEV

package server

import "net/http"

// devEnabled reports whether this binary has the dev session route.
const devEnabled = false

// registerDev adds nothing: release and default builds have no dev session.
func registerDev(*Server, *http.ServeMux) {}
