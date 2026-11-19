package cvetools

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/anchore/syft/syft"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/golang/protobuf/proto"
	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	scanUtils "github.com/neuvector/neuvector/share/scan"
	"github.com/neuvector/neuvector/share/utils"
)

const syftOrigin = "syft"

var syftTimeout = 300 * time.Second

// fullSBOMMaxSize is the max gzip size of the full SBOM, same as controller s3store.MaxObjectSize.
var fullSBOMMaxSize = 32 << 20

// grpcMsgMargin is the room left in a gRPC message for the other fields and the framing.
const grpcMsgMargin = 1 << 20

// grpcDefaultMaxMsg is the controller's default gRPC limit; the controller can use it
// even when this scanner has a larger CLUSTER_GRPC_MAX_MSG_SIZE_MB.
const grpcDefaultMaxMsg = 64 << 20

// syftEnabled reports whether Syft runs for this scan. The env var is used because
// the scanner forks the scannerTask process, which inherits the environment.
// SCANNER_DISABLE_SYFT takes the values of strconv.ParseBool; an invalid value keeps Syft on.
func syftEnabled(fromRawData bool) bool {
	if !fromRawData {
		log.Debug("syft skipped: layer cacher is enabled")
		return false
	}
	if env := os.Getenv("SCANNER_DISABLE_SYFT"); env != "" {
		v, err := strconv.ParseBool(env)
		if err != nil {
			log.WithFields(log.Fields{"value": env}).Warn("invalid SCANNER_DISABLE_SYFT, syft stays enabled")
		} else if v {
			return false
		}
	}
	return true
}

// buildSyftTree creates directories and hard links only. Symlinks are never created,
// because Syft could follow them out of root.
func buildSyftTree(ctx context.Context, fileMap map[string]string, root string) error {
	root = filepath.Clean(root)
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		return fmt.Errorf("invalid syft root %q: %v", root, err)
	}
	var dirs, links, skipped, errs int
	for in, real := range fileMap {
		if ctx.Err() != nil {
			return ctx.Err()
		}
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
	if links == 0 {
		return fmt.Errorf("no files linked")
	}
	return nil
}

func runSyft(ctx context.Context, root string) (*sbom.SBOM, error) {
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
	return s, nil
}

// syftSBOM runs Syft with a timeout. It returns nil on any error, so the scan is unchanged.
func syftSBOM(ctx context.Context, root string) (res *sbom.SBOM) {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{"panic": r}).Warn("syft panicked")
			res = nil
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, syftTimeout)
	defer cancel()
	start := time.Now()
	s, err := runSyft(ctx, root)
	if err != nil {
		log.WithFields(log.Fields{"error": err, "duration": time.Since(start)}).Warn("syft failed")
		return nil
	}
	log.WithFields(log.Fields{"packages": s.Artifacts.Packages.PackageCount(), "duration": time.Since(start)}).Info("syft done")
	return s
}

// setFullSBOM puts the full Syft document (CycloneDX JSON, gzip) in result.
// It never fails the scan: on any problem the fields stay empty.
func setFullSBOM(result *share.ScanResult, s *sbom.SBOM, req *share.ScanImageRequest, imageID string) {
	if !req.IncludeFullSBOM || s == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{"panic": r}).Warn("full sbom panicked")
			result.FullSBOM, result.FullSBOMFormat = nil, ""
		}
	}()
	start := time.Now()
	ref := req.Repository
	if strings.HasPrefix(req.Tag, "sha256:") {
		ref += "@" + req.Tag
	} else if req.Tag != "" {
		ref += ":" + req.Tag
	}
	cp := *s // shallow copy: the caller's SBOM keeps its source
	// the directory source would expose the temp path
	cp.Source = source.Description{
		Name:    req.Repository,
		Version: result.Digest,
		Metadata: source.ImageMetadata{
			UserInput:      ref,
			ID:             imageID,
			ManifestDigest: result.Digest,
		},
	}
	cfg := cyclonedxjson.DefaultEncoderConfig()
	cfg.Version = "1.6" // fixed spec version (D4), not the Syft default
	enc, err := cyclonedxjson.NewFormatEncoderWithConfig(cfg)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("full sbom encoder failed")
		return
	}
	doc, err := format.Encode(cp, enc)
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("full sbom encoding failed")
		return
	}
	gz := utils.GzipBytes(doc)
	if len(gz) > fullSBOMMaxSize {
		log.WithFields(log.Fields{"size": len(gz), "max": fullSBOMMaxSize}).Warn("full sbom too big, skipped")
		return
	}
	result.FullSBOM, result.FullSBOMFormat = gz, share.FullSBOMFormatCycloneDX
	if size, limit := proto.Size(result), min(cluster.GRPCMaxMsgSize, grpcDefaultMaxMsg)-grpcMsgMargin; size > limit {
		log.WithFields(log.Fields{"size": size, "limit": limit, "sbom": len(gz)}).Warn("full sbom does not fit the gRPC message, skipped")
		result.FullSBOM, result.FullSBOMFormat = nil, ""
		return
	}
	log.WithFields(log.Fields{"gzip": len(gz), "json": len(doc), "duration": time.Since(start)}).Info("full sbom done")
}

// startSyft creates a temp dir under imgPath and runs buildSyftTree and Syft in the background.
// The result channel is nil when Syft is skipped. Use waitSyft with the returned deadline.
func startSyft(ctx context.Context, imgPath string, fileMap map[string]string) (<-chan *sbom.SBOM, time.Time) {
	dir, err := os.MkdirTemp(imgPath, "syft-")
	if err != nil {
		log.WithFields(log.Fields{"error": err}).Warn("syft skipped")
		return nil, time.Time{}
	}
	ch := make(chan *sbom.SBOM, 1) // buffered: the goroutine never blocks, even if nobody waits
	start := time.Now()
	// one budget for tree build and Syft, so the wait deadline below matches it
	sctx, cancel := context.WithDeadline(ctx, start.Add(syftTimeout))
	go func() {
		defer cancel()
		defer os.RemoveAll(dir)
		if err := buildSyftTree(sctx, fileMap, dir); err != nil {
			log.WithFields(log.Fields{"error": err}).Warn("syft skipped")
			ch <- nil
			return
		}
		ch <- syftSBOM(sctx, dir)
	}()
	return ch, start.Add(syftTimeout + 10*time.Second)
}

// waitSyft waits for the Syft result until deadline. Catalogers can ignore ctx, so the wait is bounded.
func waitSyft(ch <-chan *sbom.SBOM, deadline time.Time) *sbom.SBOM {
	select { // a finished result wins even when the deadline has passed
	case s := <-ch:
		return s
	default:
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case s := <-ch:
		return s
	case <-t.C:
		log.Warn("syft result not ready, skipped")
		return nil
	}
}

// javaFiles returns the unique in-image paths of a Syft package. AccessPath only: nested jars
// keep RealPath = outer jar and AccessPath = "outer:inner", like NeuVector's File.
// shortcut: NV File keeps only the outer jar and the innermost entry while Syft chains every level,
// so jars nested 2+ levels deep do not match by file; upgrade with the share/scan jar source change.
func javaFiles(p pkg.Package) []string {
	var out []string
	for _, l := range p.Locations.ToSlice() {
		f := l.AccessPath
		if f == "" {
			f = l.RealPath
		}
		out = appendUnique(out, f)
	}
	return out
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

// apkNamespace returns the namespace of an apk purl merge key "apk/<ns>/<name>@<ver>".
func apkNamespace(key string) (string, bool) {
	parts := strings.SplitN(key, "/", 3)
	if len(parts) == 3 && parts[0] == "apk" {
		return parts[1], true
	}
	return "", false
}

// mergeSyftModules adds Syft licenses to matching NeuVector modules and appends
// Syft-only packages. CVE matching is not changed.
func mergeSyftModules(modules []*share.ScanModule, pkgs []pkg.Package) []*share.ScanModule {
	nv := make(map[string][]*share.ScanModule)
	apkOrigin := make(map[string][]*share.ScanModule) // NV folds apk subpackages into the origin module
	jarFile := make(map[string][]*share.ScanModule)   // jar modules by file+version
	for _, m := range modules {
		if k := scanUtils.PurlMergeKey(m.Purl); k != "" {
			nv[k] = append(nv[k], m)
			if ns, ok := apkNamespace(k); ok {
				ak := "apk/" + ns + "/" + strings.ToLower(m.Name) + "@" + m.Version
				apkOrigin[ak] = append(apkOrigin[ak], m)
			}
		}
		if m.Source == "jar" {
			fk := "/" + m.File + "@" + m.Version
			jarFile[fk] = append(jarFile[fk], m)
		}
	}
	// jar file matching is used only when the file has exactly one Syft package of that version
	// (shaded jars have several), and never moves a module whose own purl matches a Syft package.
	syftKeys := make(map[string]bool)
	jarSyft := make(map[string]int)
	for _, p := range pkgs {
		if k := scanUtils.PurlMergeKey(p.PURL); k != "" {
			syftKeys[k] = true
		}
		if p.Type == pkg.JavaPkg {
			for _, f := range javaFiles(p) {
				jarSyft[f+"@"+p.Version]++
			}
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
		ms, ok := nv[key]
		if !ok {
			if e, isApk := p.Metadata.(pkg.ApkDBEntry); isApk && e.OriginPackage != "" {
				if ns, ok2 := apkNamespace(key); ok2 {
					ms, ok = apkOrigin["apk/"+ns+"/"+strings.ToLower(e.OriginPackage)+"@"+p.Version]
					ok = ok && len(ms) > 0
				}
			}
		}
		if p.Type == pkg.JavaPkg {
			for _, f := range javaFiles(p) {
				if jarSyft[f+"@"+p.Version] != 1 {
					continue
				}
				for _, m := range jarFile[f+"@"+p.Version] {
					if mk := scanUtils.PurlMergeKey(m.Purl); mk != key && syftKeys[mk] {
						continue
					}
					m.Purl = p.PURL // Syft reads pom, manifest and file name; NV has none or a heuristic one
					if !slices.Contains(nv[key], m) {
						nv[key] = append(nv[key], m)
					}
				}
			}
			ms = nv[key]
			ok = len(ms) > 0
		}
		if ok {
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
