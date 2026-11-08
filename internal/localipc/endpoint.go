package localipc

import "strings"

// Windows names a local endpoint by a hash of the user's SID and the
// endpoint's path. The same file can be spelled in several ways on Windows:
// with 8.3 short components ("RUNNER~1") or long ones ("runneradmin"), and in
// any letter case. Earlier versions hashed the spelling they were given
// (lowercased), so a server listening on a short spelling and a client dialing
// the long spelling computed different pipe names, and the client reported the
// live session as gone.
//
// endpointKeys returns the text hashed for an endpoint path abs (absolute):
//
//   - canonical: the long-path spelling, lowercased. Listen uses only this.
//     For an endpoint already spelled in long form it equals the old key, so
//     clients of older versions still reach new servers in the common case.
//   - legacy: further keys that a server of an older version may have used,
//     lowercased, excluding canonical and duplicates: the given spelling, the
//     short spelling, and the short spelling of the DIRECTORY joined with the
//     long (and the given) name of the endpoint file. An older server hashed
//     the spelling it had before it created the endpoint file; on a volume
//     with 8.3 names that file can later get its own short alias
//     ("012345~1.SOC"), which the short spelling of the whole path would then
//     use instead of the name the server hashed. Dial tries them, in order,
//     only when no pipe answers under the canonical name.
//
// long and short convert an existing path (GetLongPathName and
// GetShortPathName on Windows). An endpoint file usually does not exist yet
// when Listen runs: the deepest existing ancestor is converted and the
// remaining components are kept as given.
func endpointKeys(abs string, long, short func(string) (string, error)) (canonical string, legacy []string) {
	longAbs := convertExisting(abs, long)
	canonical = strings.ToLower(longAbs)
	keys := []string{abs, convertExisting(abs, short)}
	if dir, leaf, ok := splitLeaf(abs); ok {
		shortDir := convertExisting(dir, short)
		if _, longLeaf, ok := splitLeaf(longAbs); ok {
			keys = append(keys, shortDir+longLeaf)
		}
		keys = append(keys, shortDir+leaf)
	}
	seen := map[string]bool{canonical: true}
	for _, k := range keys {
		k = strings.ToLower(k)
		if !seen[k] {
			seen[k] = true
			legacy = append(legacy, k)
		}
	}
	return canonical, legacy
}

// splitLeaf splits p before its last component: "C:\a\b.sock" gives
// "C:\a" and "\b.sock" (the separator stays with the leaf). ok is false for
// a path without a parent directory.
func splitLeaf(p string) (dir, leaf string, ok bool) {
	i := strings.LastIndexAny(p, `\/`)
	if i <= 0 || i == len(p)-1 {
		return "", "", false
	}
	if strings.HasSuffix(p[:i], ":") { // "C:\x": the parent is the drive root "C:\"
		return p[:i+1], p[i+1:], true
	}
	return p[:i], p[i:], true
}

// convertExisting applies conv to the longest existing prefix of p (a path
// with \ or / separators) and appends the rest unchanged. If no prefix can be
// converted, p is returned as given.
func convertExisting(p string, conv func(string) (string, error)) string {
	if c, err := conv(p); err == nil && c != "" {
		return c
	}
	i := strings.LastIndexAny(p, `\/`)
	if i <= 0 || i == len(p)-1 {
		return p
	}
	dir, rest := p[:i], p[i:]
	if strings.HasSuffix(dir, ":") { // "C:" alone is the drive's current directory
		dir, rest = p[:i+1], p[i+1:]
		if c, err := conv(dir); err == nil && c != "" {
			return strings.TrimRight(c, `\/`) + `\` + rest
		}
		return p
	}
	return convertExisting(dir, conv) + rest
}
