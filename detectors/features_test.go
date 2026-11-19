package detectors

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func parseDeb(t *testing.T, data string) []FeatureVersion {
	m := map[string]FeatureVersion{}
	require.NoError(t, parseDPKGFeatureFile(m, data, false, true))
	var out []FeatureVersion
	for _, v := range m {
		out = append(out, v)
	}
	return out
}

func TestDPKGPurlVersion(t *testing.T) {
	fvs := parseDeb(t, "Package: bash\nSource: bash (5.2.15-2)\nVersion: 5.2.15-2+b13\n\n")
	require.Len(t, fvs, 1)
	assert.Equal(t, "bash/bash", fvs[0].Package)
	assert.Equal(t, "5.2.15-2", fvs[0].Version.String())
	assert.Equal(t, "5.2.15-2+b13", fvs[0].PurlVersion)

	fvs = parseDeb(t, "Package: bsdutils\nSource: util-linux (2.38.1-5+deb12u3)\nVersion: 1:2.38.1-5+deb12u3\n\n")
	require.Len(t, fvs, 1)
	assert.Equal(t, "2.38.1-5+deb12u3", fvs[0].Version.String())
	assert.Equal(t, "1:2.38.1-5+deb12u3", fvs[0].PurlVersion)

	fvs = parseDeb(t, "Package: curl\nVersion: 7.88.1-10\n\n")
	require.Len(t, fvs, 1)
	assert.Equal(t, "curl", fvs[0].Package)
	assert.Equal(t, "", fvs[0].PurlVersion)
}

func TestAPKPurlName(t *testing.T) {
	db := "P:libressl2.7-libcrypto\nV:2.7.5-r0\no:libressl\n\n" +
		"P:libressl2.7-libssl\nV:2.7.5-r0\no:libressl\n\n" +
		"P:musl\nV:1.1.19-r10\no:musl\n\n"
	files := map[string]*FeatureFile{"lib/apk/db/installed": {Data: []byte(db)}}
	fvs, err := detectAPK("alpine:3.8", files, "")
	require.NoError(t, err)
	got := map[string]FeatureVersion{}
	for _, f := range fvs {
		got[f.Package] = f
	}
	require.Len(t, got, 2)
	assert.Equal(t, "libressl2.7-libcrypto", got["libressl"].PurlName)
	assert.Equal(t, "2.7.5-r0", got["libressl"].Version.String())
	assert.Equal(t, "", got["musl"].PurlName)
}

func TestAPKPurlNameOriginBinaryLater(t *testing.T) {
	db := "P:libssl3\nV:3.1.4-r0\no:openssl\n\n" + "P:openssl\nV:3.1.4-r0\no:openssl\n\n"
	fvs, err := detectAPK("alpine:3.19", map[string]*FeatureFile{"lib/apk/db/installed": {Data: []byte(db)}}, "")
	require.NoError(t, err)
	require.Len(t, fvs, 1)
	assert.Equal(t, "openssl", fvs[0].Package)
	assert.Equal(t, "", fvs[0].PurlName)
}
