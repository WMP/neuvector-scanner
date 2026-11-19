package cvetools

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source/directorysource"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	scanUtils "github.com/neuvector/neuvector/share/scan"
)

const syftOrigin = "syft"

var syftTimeout = 300 * time.Second

// syftEnabled reports whether Syft runs for this scan. The env var is used because
// the scanner forks the scannerTask process, which inherits the environment.
func syftEnabled(fromRawData bool) bool {
	if !fromRawData {
		log.Info("syft skipped: layer cacher is enabled")
		return false
	}
	if v, err := strconv.ParseBool(os.Getenv("SCANNER_DISABLE_SYFT")); err == nil && v {
		return false
	}
	return true
}

// buildSyftTree creates directories and hard links only. Symlinks are never created,
// because Syft could follow them out of root.
func buildSyftTree(fileMap map[string]string, root string) error {
	root = filepath.Clean(root)
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return fmt.Errorf("invalid syft root %q: %v", root, err)
	}
	var dirs, links, skipped, errs int
	for in, real := range fileMap {
		dst := filepath.Join(root, in)
		if dst != root && !strings.HasPrefix(dst, root+string(filepath.Separator)) {
			errs++
			continue
		}
		fi, err := os.Lstat(real)
		switch {
		case err != nil:
			errs++
		case fi.IsDir():
			if err := os.MkdirAll(dst, 0o755); err != nil {
				errs++
			} else {
				dirs++
			}
		case fi.Mode().IsRegular():
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				errs++
			} else if err := os.Link(real, dst); err != nil && !os.IsExist(err) {
				errs++
			} else {
				links++
			}
		default:
			skipped++
		}
	}
	log.WithFields(log.Fields{"dirs": dirs, "links": links, "skipped": skipped, "errors": errs}).Info("syft tree")
	return nil
}

func runSyft(ctx context.Context, root string) ([]pkg.Package, error) {
	src, err := directorysource.New(directorysource.Config{Path: root, Base: root})
	if err != nil {
		return nil, err
	}
	if c, ok := src.(io.Closer); ok {
		defer c.Close()
	}
	// Image catalogers are required: the directory ones miss installed packages.
	cfg := syft.DefaultCreateSBOMConfig().
		WithCatalogerSelection(cataloging.NewSelectionRequest().WithDefaults(pkgcataloging.ImageTag)).
		WithoutFiles()
	s, err := syft.CreateSBOM(ctx, src, cfg)
	if err == nil {
		err = ctx.Err() // Syft can return partial results on timeout
	}
	if err != nil {
		return nil, err
	}
	return s.Artifacts.Packages.Sorted(), nil
}

// syftPackages runs Syft with a timeout. It returns nil on any error, so the scan is unchanged.
func syftPackages(ctx context.Context, root string) []pkg.Package {
	ctx, cancel := context.WithTimeout(ctx, syftTimeout)
	defer cancel()
	start := time.Now()
	pkgs, err := runSyft(ctx, root)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "duration": time.Since(start)}).Warn("syft failed")
		return nil
	}
	log.WithFields(log.Fields{"packages": len(pkgs), "duration": time.Since(start)}).Info("syft done")
	return pkgs
}

// startSyft builds the tree under imgPath and runs Syft in the background.
// The result channel is nil when Syft is skipped.
func startSyft(ctx context.Context, imgPath string, fileMap map[string]string) <-chan []pkg.Package {
	dir, err := os.MkdirTemp(imgPath, "syft-")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("syft skipped")
		return nil
	}
	if err := buildSyftTree(fileMap, dir); err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("syft skipped")
		os.RemoveAll(dir)
		return nil
	}
	ch := make(chan []pkg.Package, 1)
	go func() {
		defer os.RemoveAll(dir)
		ch <- syftPackages(ctx, dir)
	}()
	return ch
}

func syftLicenses(p pkg.Package) []string {
	var out []string
	for _, l := range p.Licenses.ToSlice() {
		if l.SPDXExpression != "" {
			out = appendUnique(out, l.SPDXExpression)
		} else {
			out = appendUnique(out, l.Value)
		}
	}
	return out
}

func appendUnique(list []string, items ...string) []string {
outer:
	for _, it := range items {
		if it == "" {
			continue
		}
		for _, e := range list {
			if e == it {
				continue outer
			}
		}
		list = append(list, it)
	}
	return list
}

// mergeSyftModules adds Syft licenses to matching NeuVector modules and appends
// Syft-only packages. CVE matching is not changed.
func mergeSyftModules(modules []*share.ScanModule, pkgs []pkg.Package) []*share.ScanModule {
	nv := make(map[string][]*share.ScanModule)
	for _, m := range modules {
		if k := scanUtils.PurlMergeKey(m.Purl); k != "" {
			nv[k] = append(nv[k], m)
		}
	}
	added := make(map[string]*share.ScanModule)
	var matched, skipped int
	for _, p := range pkgs {
		key := scanUtils.PurlMergeKey(p.PURL)
		if key == "" {
			skipped++
			continue
		}
		lics := syftLicenses(p)
		if ms, ok := nv[key]; ok {
			matched++
			for _, m := range ms { // NV module wins; its Purl is set, it gave the key
				m.Licenses = appendUnique(m.Licenses, lics...)
			}
		} else if m, ok := added[key]; ok {
			m.Licenses = appendUnique(m.Licenses, lics...)
		} else {
			m := &share.ScanModule{Name: p.Name, Version: p.Version, Source: string(p.Type), Purl: p.PURL, Licenses: lics, Origin: syftOrigin}
			added[key] = m
			modules = append(modules, m)
		}
	}
	log.WithFields(log.Fields{"matched": matched, "added": len(added), "skipped": skipped}).Info("syft merge")
	return modules
}
