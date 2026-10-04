// Package buildinfo reports which commit the running binary was built from.
//
// The Go toolchain stamps vcs.revision, vcs.modified and vcs.time into every
// binary built inside a git checkout, so no linker flags are needed.
package buildinfo

import "runtime/debug"

// Info is served by GET /api/version and shown in the apps' Settings.
type Info struct {
	Revision string `json:"revision"`       // full commit hash, or "unknown"
	Short    string `json:"short"`          // first 7 characters, with "-dirty" when modified
	Modified bool   `json:"modified"`       // built from a tree with uncommitted changes
	Time     string `json:"time,omitempty"` // commit time, RFC 3339
	Go       string `json:"go"`             // toolchain version
}

// Read returns the build information of the running binary.
func Read() Info {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return Info{Revision: "unknown", Short: "unknown"}
	}
	return fromSettings(bi.GoVersion, bi.Settings)
}

func fromSettings(goVersion string, settings []debug.BuildSetting) Info {
	info := Info{Revision: "unknown", Go: goVersion}
	for _, s := range settings {
		switch s.Key {
		case "vcs.revision":
			info.Revision = s.Value
		case "vcs.modified":
			info.Modified = s.Value == "true"
		case "vcs.time":
			info.Time = s.Value
		}
	}
	info.Short = info.Revision
	if len(info.Short) > 7 {
		info.Short = info.Short[:7]
	}
	if info.Modified {
		info.Short += "-dirty"
	}
	return info
}
