package cvetools

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/share"
)

func TestSyftEnabled(t *testing.T) {
	t.Setenv("SCANNER_DISABLE_SYFT", "")
	assert.True(t, syftEnabled(true))
	assert.False(t, syftEnabled(false))
	t.Setenv("SCANNER_DISABLE_SYFT", "true")
	assert.False(t, syftEnabled(true))
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))
}

func TestBuildSyftTree(t *testing.T) {
	base := t.TempDir()
	layer := filepath.Join(base, "layer")
	root := filepath.Join(base, "root")
	require.NoError(t, os.MkdirAll(root, 0o755))
	writeFile(t, filepath.Join(layer, "a/b/file.txt"), "x")
	require.NoError(t, os.Symlink("/etc/passwd", filepath.Join(layer, "abs")))
	require.NoError(t, os.Symlink("a/b/file.txt", filepath.Join(layer, "rel")))
	writeFile(t, filepath.Join(layer, "evil"), "x")

	fm := map[string]string{
		"/a":              filepath.Join(layer, "a"),
		"/a/b":            filepath.Join(layer, "a/b"),
		"/a/b/file.txt":   filepath.Join(layer, "a/b/file.txt"),
		"/abs":            filepath.Join(layer, "abs"),
		"/rel":            filepath.Join(layer, "rel"),
		"/../../evil-out": filepath.Join(layer, "evil"),
	}
	require.NoError(t, buildSyftTree(fm, root))

	fi1, _ := os.Stat(filepath.Join(layer, "a/b/file.txt"))
	fi2, err := os.Stat(filepath.Join(root, "a/b/file.txt"))
	require.NoError(t, err)
	assert.True(t, os.SameFile(fi1, fi2))
	assert.DirExists(t, filepath.Join(root, "a/b"))

	require.NoError(t, filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		require.NoError(t, err)
		assert.Zero(t, fi.Mode()&os.ModeSymlink, p)
		return nil
	}))
	_, err = os.Lstat(filepath.Join(root, "abs"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Lstat(filepath.Join(base, "evil-out"))
	assert.True(t, os.IsNotExist(err))
	_, err = os.Lstat(filepath.Join(filepath.Dir(base), "evil-out"))
	assert.True(t, os.IsNotExist(err))

	assert.Error(t, buildSyftTree(fm, filepath.Join(base, "missing")))

	// no link created: error
	assert.Error(t, buildSyftTree(map[string]string{"/x": filepath.Join(layer, "nope")}, root))
	assert.Error(t, buildSyftTree(nil, root))

	img := t.TempDir()
	assert.Nil(t, startSyft(context.Background(), img, nil))
	entries, err := os.ReadDir(img)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

const dpkgStatus = `Package: bash
Status: install ok installed
Architecture: amd64
Version: 5.2.15-2+b13
Maintainer: x <x@example.com>
Description: shell
`

func TestRunSyft(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), dpkgStatus)
	writeFile(t, filepath.Join(root, "etc/os-release"), "ID=debian\nVERSION_ID=12\n")
	writeFile(t, filepath.Join(root, "usr/lib/node_modules/foo/package.json"), `{"name":"foo","version":"1.2.3","license":"MIT"}`)

	pkgs, err := runSyft(context.Background(), root)
	require.NoError(t, err)
	var deb, npm bool
	for _, p := range pkgs {
		if p.Type == pkg.DebPkg && p.Name == "bash" {
			deb = true
			assert.Contains(t, p.PURL, "pkg:deb/debian/bash")
		}
		if p.Type == pkg.NpmPkg && p.Name == "foo" {
			npm = true
		}
	}
	assert.True(t, deb, "deb package")
	assert.True(t, npm, "npm package")
}

func TestSyftPackagesTimeout(t *testing.T) {
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "var/lib/dpkg/status"), dpkgStatus)

	old := syftTimeout
	syftTimeout = time.Nanosecond
	defer func() { syftTimeout = old }()

	pkgs := syftPackages(context.Background(), root)
	assert.Empty(t, pkgs)

	nv := []*share.ScanModule{{Name: "a", Version: "1"}}
	out := mergeSyftModules(nv, pkgs)
	assert.Equal(t, nv, out)

	cctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := runSyft(cctx, root)
	assert.Error(t, err)
}

func sp(name, version string, typ pkg.Type, purl string, lics ...string) pkg.Package {
	var ls []pkg.License
	for _, l := range lics {
		ls = append(ls, pkg.NewLicense(l))
	}
	return pkg.Package{Name: name, Version: version, Type: typ, PURL: purl, Licenses: pkg.NewLicenseSet(ls...)}
}

func TestMergeSyftModules(t *testing.T) {
	vul := &share.ScanVulnerability{Name: "CVE-2021-44228"}
	cases := []struct{ name, nvPurl, syftPurl string }{
		{"jar", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
		{"jar qualifier", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar"},
		{"python", "pkg:pypi/foo-bar@1.0", "pkg:pypi/Foo_Bar@1.0"},
		{"go", "pkg:golang/github.com/x/y@v1.2.3", "pkg:golang/github.com/x/y@v1.2.3"},
		{"deb", "pkg:deb/debian/bash@5.2.15-2%2Bb13?distro=debian-12", "pkg:deb/debian/bash@5.2.15-2+b13?arch=amd64&distro=debian-12"},
		{"apk", "pkg:apk/alpine/libressl2.7-libcrypto@2.7.5-r0?distro=alpine-3.8", "pkg:apk/alpine/libressl2.7-libcrypto@2.7.5-r0?arch=x86_64&upstream=libressl&distro=alpine-3.8"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			nv := &share.ScanModule{Name: "nvname", Version: "nvver", Source: "nvsrc", Purl: c.nvPurl, Vuls: []*share.ScanModuleVul{{Name: vul.Name}}, Licenses: []string{"MIT"}}
			p := sp("syftname", "syftver", pkg.JavaPkg, c.syftPurl, "MIT", "Apache-2.0")
			out := mergeSyftModules([]*share.ScanModule{nv}, []pkg.Package{p})
			require.Len(t, out, 1)
			assert.Equal(t, "nvname", out[0].Name)
			assert.Equal(t, "nvver", out[0].Version)
			assert.Equal(t, "nvsrc", out[0].Source)
			assert.Equal(t, c.nvPurl, out[0].Purl)
			assert.Len(t, out[0].Vuls, 1)
			assert.Equal(t, []string{"MIT", "Apache-2.0"}, out[0].Licenses)
		})
	}
}

func TestMergeSyftModulesAddedAndSkipped(t *testing.T) {
	nv := &share.ScanModule{Name: "n", Version: "1"}
	pkgs := []pkg.Package{
		sp("busybox", "1.36.1", pkg.BinaryPkg, "pkg:generic/busybox@1.36.1", "GPL-2.0-only"),
		sp("busybox", "1.36.1", pkg.BinaryPkg, "pkg:generic/busybox@1.36.1", "GPL-2.0-only", "MIT"),
		sp("nopurl", "1", pkg.BinaryPkg, ""),
	}
	out := mergeSyftModules([]*share.ScanModule{nv}, pkgs)
	require.Len(t, out, 2)
	assert.Equal(t, "n", out[0].Name)
	assert.Equal(t, "busybox", out[1].Name)
	assert.Equal(t, "syft", out[1].Origin)
	assert.Equal(t, "binary", out[1].Source)
	assert.Empty(t, out[1].Vuls)
	assert.Equal(t, []string{"GPL-2.0-only", "MIT"}, out[1].Licenses)
}

func apkPkg(name, origin string) pkg.Package {
	p := sp(name, "2.7.5-r0", pkg.ApkPkg, "pkg:apk/alpine/"+name+"@2.7.5-r0?arch=x86_64&distro=alpine-3.8.4&upstream="+origin, "lic-"+name)
	p.Metadata = pkg.ApkDBEntry{Package: name, OriginPackage: origin, Version: "2.7.5-r0"}
	return p
}

func TestMergeSyftModulesApkOrigin(t *testing.T) {
	nv := &share.ScanModule{Name: "libressl", Version: "2.7.5-r0", Source: "alpine:3.8",
		Purl: "pkg:apk/alpine/libressl2.7-libcrypto@2.7.5-r0?distro=alpine-3.8", Vuls: []*share.ScanModuleVul{{Name: "CVE-1"}}}
	pkgs := []pkg.Package{apkPkg("libressl2.7-libcrypto", "libressl"), apkPkg("libressl2.7-libssl", "libressl"), apkPkg("libressl2.7-libtls", "libressl")}
	out := mergeSyftModules([]*share.ScanModule{nv}, pkgs)
	require.Len(t, out, 1)
	assert.Len(t, out[0].Vuls, 1)
	assert.ElementsMatch(t, []string{"lic-libressl2.7-libcrypto", "lic-libressl2.7-libssl", "lic-libressl2.7-libtls"}, out[0].Licenses)

	out = mergeSyftModules([]*share.ScanModule{nv}, []pkg.Package{apkPkg("other-sub", "other")})
	require.Len(t, out, 2)
	assert.Equal(t, "syft", out[1].Origin)
}

func jarPkg(version, path string) pkg.Package {
	p := sp("log4j-core", version, pkg.JavaPkg, "pkg:maven/org.apache.logging.log4j/log4j-core@"+version, "Apache-2.0")
	p.Locations = file.NewLocationSet(file.NewLocation(path))
	return p
}

func TestMergeSyftModulesJarFile(t *testing.T) {
	newNV := func(src string) *share.ScanModule {
		return &share.ScanModule{Name: "org.apache.logging.log4j:Apache Log4j Core", Version: "2.14.1", Source: src,
			File: "app/lib/log4j-core-2.14.1.jar", Vuls: []*share.ScanModuleVul{{Name: "CVE-2021-44228"}}}
	}
	p := jarPkg("2.14.1", "/app/lib/log4j-core-2.14.1.jar")
	out := mergeSyftModules([]*share.ScanModule{newNV("jar")}, []pkg.Package{p})
	require.Len(t, out, 1)
	assert.Equal(t, "org.apache.logging.log4j:Apache Log4j Core", out[0].Name)
	assert.Len(t, out[0].Vuls, 1)
	assert.Equal(t, p.PURL, out[0].Purl)
	assert.Equal(t, []string{"Apache-2.0"}, out[0].Licenses)

	// nested jar: matched through AccessPath
	nested := newNV("jar")
	nested.File = "app.jar:BOOT-INF/lib/log4j-core-2.14.1.jar"
	np := jarPkg("2.14.1", "/app.jar")
	for _, l := range np.Locations.ToSlice() {
		l.AccessPath = "/app.jar:BOOT-INF/lib/log4j-core-2.14.1.jar"
		np.Locations = file.NewLocationSet(l)
	}
	assert.Len(t, mergeSyftModules([]*share.ScanModule{nested}, []pkg.Package{np}), 1)

	// different version: added
	out = mergeSyftModules([]*share.ScanModule{newNV("jar")}, []pkg.Package{jarPkg("2.15.0", "/app/lib/log4j-core-2.14.1.jar")})
	require.Len(t, out, 2)
	assert.Empty(t, out[0].Purl)

	// other ecosystems are not matched by file
	out = mergeSyftModules([]*share.ScanModule{newNV("php")}, []pkg.Package{p})
	require.Len(t, out, 2)
	assert.Empty(t, out[0].Purl)
}

func TestSyftLicensesPreferSPDX(t *testing.T) {
	l := pkg.License{Value: "The MIT License", SPDXExpression: "MIT"}
	p := pkg.Package{Licenses: pkg.NewLicenseSet(l, pkg.License{Value: "Custom"})}
	assert.ElementsMatch(t, []string{"MIT", "Custom"}, syftLicenses(p))
}
