package scan

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/neuvector/neuvector/share"
)

// Package URL (ECMA-427) support; port of the S1 spike (s1purl.py).

var pypiSep = regexp.MustCompile(`[-_.]+`)

// Case folding per purl type definition.
var (
	purlLowerNamespace = map[string]bool{"apk": true, "composer": true, "deb": true, "golang": true, "rpm": true}
	purlLowerName      = map[string]bool{"apk": true, "composer": true, "deb": true, "golang": true, "pypi": true}
)

// purlOS maps a NeuVector distro ID to purl type and namespace.
var purlOS = map[string][2]string{
	"debian": {"deb", "debian"}, "ubuntu": {"deb", "ubuntu"}, "alpine": {"apk", "alpine"},
	"wolfi": {"apk", "wolfi"}, "chainguard": {"apk", "chainguard"}, "rhel": {"rpm", "redhat"},
	"centos": {"rpm", "centos"}, "fedora": {"rpm", "fedora"}, "amzn": {"rpm", "amzn"}, "ol": {"rpm", "ol"},
	"rocky": {"rpm", "rocky"}, "almalinux": {"rpm", "almalinux"}, "mariner": {"rpm", "mariner"},
	"azurelinux": {"rpm", "azurelinux"}, "photon": {"rpm", "photon"}, "sles": {"rpm", "sles"},
	"opensuse-leap": {"rpm", "opensuse"}, "opensuse-tumbleweed": {"rpm", "opensuse"},
	"rhcos": {"rpm", "rhcos"}, "suse-liberty": {"rpm", "suse-liberty"}, "sl-micro": {"rpm", "sl-micro"},
	"sle-micro": {"rpm", "sle-micro"},
}

// escapePurl percent-encodes like Python quote(s, safe=":").
func escapePurl(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~:", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func escapePurlPath(p string, drop bool) string {
	var out []string
	for _, s := range strings.Split(strings.Trim(p, "/"), "/") {
		if drop && (s == "" || s == "." || s == "..") {
			continue
		}
		out = append(out, escapePurl(s))
	}
	return strings.Join(out, "/")
}

// foldPurl lowercases namespace and name as the purl type definition demands.
func foldPurl(typ, ns, name string) (string, string) {
	if purlLowerNamespace[typ] {
		ns = strings.ToLower(ns)
	}
	if purlLowerName[typ] {
		name = strings.ToLower(name)
	}
	if typ == "pypi" {
		name = pypiSep.ReplaceAllString(name, "-")
	}
	return ns, name
}

// BuildPurl returns a package URL (ECMA-427), or "" when typ or name is empty.
func BuildPurl(typ, namespace, name, version string, qualifiers map[string]string, subpath string) string {
	typ = strings.ToLower(typ)
	if typ == "" || name == "" {
		return ""
	}
	namespace, name = foldPurl(typ, namespace, name)
	s := "pkg:" + typ + "/"
	if namespace != "" {
		s += escapePurlPath(namespace, false) + "/"
	}
	s += escapePurl(name)
	if version != "" {
		s += "@" + escapePurl(version)
	}
	q := map[string]string{}
	for k, v := range qualifiers {
		if v != "" {
			q[strings.ToLower(k)] = v
		}
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sep := "?"
	for _, k := range keys {
		s += sep + k + "=" + escapePurl(q[k])
		sep = "&"
	}
	if subpath != "" {
		s += "#" + escapePurlPath(subpath, true)
	}
	return s
}

type purlParts struct {
	typ, namespace, name, version, subpath string
	qualifiers                             map[string]string
}

// unescapePurl decodes %XX. With an invalid escape the string is returned undecoded.
func unescapePurl(s string) string {
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// parsePurl splits a purl into percent-decoded, case-folded parts.
func parsePurl(p string) (*purlParts, bool) {
	if !strings.HasPrefix(p, "pkg:") {
		return nil, false
	}
	p, sub, _ := strings.Cut(strings.TrimLeft(p[4:], "/"), "#")
	p, qs, _ := strings.Cut(p, "?")
	parts := strings.Split(p, "/")
	if len(parts) < 2 {
		return nil, false
	}
	last, ver, _ := strings.Cut(parts[len(parts)-1], "@")
	r := &purlParts{typ: strings.ToLower(parts[0]), version: unescapePurl(ver), subpath: strings.Trim(unescapePurl(sub), "/")}
	r.namespace, r.name = foldPurl(r.typ, unescapePurl(strings.Join(parts[1:len(parts)-1], "/")), unescapePurl(last))
	if r.name == "" {
		return nil, false
	}
	for _, kv := range strings.Split(qs, "&") {
		if k, v, _ := strings.Cut(kv, "="); kv != "" {
			if r.qualifiers == nil {
				r.qualifiers = map[string]string{}
			}
			r.qualifiers[strings.ToLower(k)] = unescapePurl(v)
		}
	}
	return r, true
}

// PurlMergeKey returns "type/namespace/name@version" without qualifiers and subpath,
// with case folded per purl type and the golang "v" version prefix removed.
// It returns "" when purl cannot be parsed.
func PurlMergeKey(purl string) string {
	c, ok := parsePurl(purl)
	if !ok {
		return ""
	}
	switch c.typ {
	case "golang":
		c.version = strings.TrimPrefix(c.version, "v")
	case "cran": // NeuVector lowercases R package names
		c.name = strings.ToLower(c.name)
	}
	if c.namespace != "" {
		c.namespace += "/"
	}
	return c.typ + "/" + c.namespace + c.name + "@" + c.version
}

// ModulePurl returns m.Purl when set. Otherwise it derives the purl from Source, Name
// and Version (reports from scanners without purl support). namespace is
// ScanResult.Namespace (e.g. "debian:12"), used when m.Source is empty.
// It returns "" when the module has no valid purl.
func ModulePurl(m *share.ScanModule, namespace string) string {
	if m.Purl != "" {
		return m.Purl
	}
	name, ver, src := m.Name, m.Version, m.Source
	if src == "" {
		src = namespace
	}
	gen := func(n string) string { return BuildPurl("generic", "", n, ver, nil, "") }
	pre := func(prefix string) string { return strings.TrimPrefix(name, prefix) }
	if src == "" || strings.Contains(src, ":") { // OS package: Source is "ID:VERSION"
		osid, osver, _ := strings.Cut(src, ":")
		if osid == "busybox" {
			return gen(name)
		}
		t, ok := purlOS[osid]
		if !ok {
			return ""
		}
		q := map[string]string{}
		if osver != "" {
			q["distro"] = osid + "-" + osver
		}
		if name == "opensslxx" {
			name = "openssl"
		}
		if t[0] == "deb" && strings.Contains(name, "/") {
			q["upstream"], name, _ = strings.Cut(name, "/")
		} else if t[0] == "rpm" && strings.Contains(ver, ":") {
			q["epoch"], ver, _ = strings.Cut(ver, ":")
		}
		return BuildPurl(t[0], t[1], name, ver, q, "")
	}
	switch src {
	case "jar":
		g, a, _ := strings.Cut(name, ":")
		if a == "" || g == "jar" || strings.ContainsRune(name, ' ') { // no groupId, or MANIFEST vendor/title text
			return ""
		}
		return BuildPurl("maven", g, a, ver, nil, "")
	case "npm":
		i := strings.LastIndex(name, "/")
		return BuildPurl("npm", name[:max(i, 0)], name[i+1:], ver, nil, "")
	case "python":
		return BuildPurl("pypi", "", pre("python:"), ver, nil, "")
	case "ruby":
		return BuildPurl("gem", "", pre("ruby:"), ver, nil, "")
	case "golang":
		n := pre("go:")
		ver, _, _ = strings.Cut(ver, " ")                           // "1.22.1 X:boringcrypto"
		if strings.HasPrefix(n, ".") || strings.HasPrefix(n, "/") { // local replace path, not a module path
			return ""
		}
		if n == "stdlib" {
			return BuildPurl("golang", "", n, ver, nil, "")
		}
		if ver != "" {
			ver = "v" + ver
		}
		i := strings.LastIndex(n, "/")
		return BuildPurl("golang", n[:max(i, 0)], n[i+1:], ver, nil, "")
	case ".NET":
		return BuildPurl("nuget", "", pre(".NET:"), ver, nil, "")
	case "php": // NeuVector drops the composer vendor, so only the runtime has a purl
		if name == "php:" || name == "php" {
			return gen("php")
		}
		return ""
	case "r":
		n := pre("r:") // "<repository>-<name>"; R package names have no "-"
		return BuildPurl("cran", "", n[strings.LastIndex(n, "-")+1:], ver, nil, "")
	case "Wordpress":
		return gen("wordpress")
	case "nginx", "openssl", "kubernetes", "openshift": // app copies of OS packages for CVE matching; platform
		return gen(src)
	case "busybox":
		return gen("busybox")
	}
	return BuildPurl("bitnami", "", name, ver, nil, "")
}
