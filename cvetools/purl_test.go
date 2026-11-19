package cvetools

import (
	"testing"

	"github.com/neuvector/neuvector/share/scan"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/share/utils"
	"github.com/neuvector/scanner/detectors"
)

func TestFeature2ModulePurlOS(t *testing.T) {
	v1, _ := utils.NewVersion("5.2.15-2")
	v2, _ := utils.NewVersion("2.7.5-r0")
	deb := feature2Module("debian:12", []detectors.FeatureVersion{
		{Package: "bash/bash", Version: v1, PurlVersion: "5.2.15-2+b13"},
	}, nil)
	require.Len(t, deb, 1)
	assert.Equal(t, "bash/bash", deb[0].Name)
	assert.Equal(t, "5.2.15-2", deb[0].Version)
	assert.Equal(t, "deb/debian/bash@5.2.15-2+b13", scan.PurlMergeKey(deb[0].Purl))

	apk := feature2Module("alpine:3.8", []detectors.FeatureVersion{
		{Package: "libressl", Version: v2, PurlName: "libressl2.7-libcrypto"},
	}, nil)
	assert.Equal(t, "libressl", apk[0].Name)
	assert.Equal(t, "2.7.5-r0", apk[0].Version)
	assert.Equal(t, "apk/alpine/libressl2.7-libcrypto@2.7.5-r0", scan.PurlMergeKey(apk[0].Purl))
}

func TestFeature2ModulePurlApps(t *testing.T) {
	app := func(src, name, ver string) detectors.AppFeatureVersion {
		a := detectors.AppFeatureVersion{}
		a.AppName, a.ModuleName, a.Version = src, name, ver
		return a
	}
	mods := feature2Module("debian:12", nil, []detectors.AppFeatureVersion{
		app("jar", "org.apache.logging.log4j:log4j-core", "2.14.1"),
		app("python", "python:Foo_Bar", "1.0"),
		app("golang", "go:github.com/x/y", "1.2.3"),
		app("jar", "org.apache.logging.log4j:Apache Log4j Core", "2.14.1"),
	})
	require.Len(t, mods, 4)
	assert.Equal(t, "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", mods[0].Purl)
	assert.Equal(t, "pypi/foo-bar@1.0", scan.PurlMergeKey(mods[1].Purl))
	assert.Equal(t, "pkg:golang/github.com/x/y@v1.2.3", mods[2].Purl)
	assert.Equal(t, "", mods[3].Purl)
	assert.Equal(t, "python:Foo_Bar", mods[1].Name)
	assert.Equal(t, "1.2.3", mods[2].Version)
}
