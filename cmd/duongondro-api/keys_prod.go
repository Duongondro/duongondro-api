//go:build !DEV

package main

// devSecretKeyBase is nil in release builds: SECRET_KEY_BASE is required.
var devSecretKeyBase []byte
