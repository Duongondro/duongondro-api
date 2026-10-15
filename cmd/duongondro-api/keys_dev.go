//go:build DEV

package main

// devSecretKeyBase seals a development database's columns when SECRET_KEY_BASE is
// unset, so `make serve` and `make db-setup` need no setup. DEV builds only: a
// release build has no default and refuses to start without SECRET_KEY_BASE
// (TestReleaseBinaryHasNoDevSession checks this string is not in it).
var devSecretKeyBase = []byte("duongondro DEV SECRET_KEY_BASE, for development databases only")
