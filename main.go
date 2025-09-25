package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/pprof/profile"
	"github.com/gorilla/mux"
)

//
// Embedded frontend assets
//

//go:embed web/index.html
var indexHTML []byte

//go:embed web/app.js
var appJS []byte

//go:embed web/style.css
var styleCSS []byte

//
// Data model
//

type StoredProfile struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Path          string            `json:"path"`
	SampleTypes   []string          `json:"sampleTypes"`
	PeriodType    string            `json:"periodType"`
	PeriodUnit    string            `json:"periodUnit"`
	Duration      float64           `json:"durationSec"`
	SampleCount   int               `json:"sampleCount"`
	FunctionCount int               `json:"functionCount"`
	CreatedAt     time.Time         `json:"createdAt"`
	Bytes         []byte            `json:"-"`
	Profile       *profile.Profile  `json:"-"`
	Meta          map[string]string `json:"meta,omitempty"`
}

type Bundle struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Created  time.Time        `json:"created"`
	Profiles []*StoredProfile `json:"profiles"`
}

type Store struct {
	mu       sync.RWMutex
	bundles  map[string]*Bundle
	profiles map[string]*StoredProfile

	// pprof backends (native UI), one per profile ID
	pprofMu      sync.RWMutex
	pprofTargets map[string]*url.URL
}

func NewStore() *Store {
	return &Store{
		bundles:      make(map[string]*Bundle),
		profiles:     make(map[string]*StoredProfile),
		pprofTargets: make(map[string]*url.URL),
	}
}

func (s *Store) AddBundle(b *Bundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles[b.ID] = b
	for _, p := range b.Profiles {
		s.profiles[p.ID] = p
	}
}

func (s *Store) GetBundle(id string) (*Bundle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bundles[id]
	return b, ok
}

func (s *Store) GetProfile(id string) (*StoredProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	return p, ok
}

//
// Utilities
//

func makeID(parts ...string) string {
	return strings.ReplaceAll(strings.ToLower(strings.Join(parts, "_")), " ", "-")
}

func detectAndDecompressAll(data []byte) ([]byte, int, error) {
	layers := 0
	out := data
	for len(out) >= 2 && out[0] == 0x1f && out[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(out))
		if err != nil {
			return nil, layers, err
		}
		dec, err := io.ReadAll(gr)
		_ = gr.Close()
		if err != nil {
			return nil, layers, err
		}
		out = dec
		layers++
	}
	return out, layers, nil
}

func parseProfile(name string, data []byte) (*profile.Profile, error) {
	buf, _, err := detectAndDecompressAll(data)
	if err != nil {
		return nil, fmt.Errorf("decompress %s: %w", name, err)
	}
	p, err := profile.Parse(bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", name, err)
	}
	return p, nil
}

func loadBundleFromZip(r io.ReaderAt, size int64, filename string) (*Bundle, error) {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return nil, err
	}
	b := &Bundle{
		ID:      makeID(filepath.Base(filename), time.Now().Format("20060102150405")),
		Name:    filepath.Base(filename),
		Created: time.Now(),
	}
	var profs []*StoredProfile
	for _, f := range zr.File {
		if !strings.HasPrefix(f.Name, "pprof/") {
			continue
		}
		lower := strings.ToLower(f.Name)
		if !(strings.HasSuffix(lower, ".pprof") ||
			strings.HasSuffix(lower, ".pprof.gz") ||
			strings.HasSuffix(lower, ".prof.gz") ||
			strings.HasSuffix(lower, ".pb.gz")) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			log.Printf("open %s: %v", f.Name, err)
			continue
		}
		content, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			log.Printf("read %s: %v", f.Name, err)
			continue
		}
		p, err := parseProfile(f.Name, content)
		if err != nil {
			log.Printf("parse %s: %v", f.Name, err)
			continue
		}

		meta := map[string]string{}
		if cmdlineFile := findSibling(zr, "pprof/cmdline.txt"); cmdlineFile != nil {
			if rc2, err := cmdlineFile.Open(); err == nil {
				if bb, err := io.ReadAll(rc2); err == nil {
					meta["cmdline.txt"] = strings.TrimSpace(string(bb))
				}
				_ = rc2.Close()
			}
		}

		sp := &StoredProfile{
			ID:            makeID(b.ID, filepath.Base(f.Name)),
			Name:          filepath.Base(f.Name),
			Path:          f.Name,
			SampleTypes:   sampleTypeStrings(p),
			PeriodType:    valueOr(p.PeriodType, func(v *profile.ValueType) string { return v.Type }),
			PeriodUnit:    valueOr(p.PeriodType, func(v *profile.ValueType) string { return v.Unit }),
			Duration:      profileDurationSec(p),
			SampleCount:   len(p.Sample),
			FunctionCount: len(p.Function),
			Bytes:         content,
			Profile:       p,
			Meta:          meta,
			CreatedAt:     time.Now(),
		}
		profs = append(profs, sp)
	}
	if len(profs) == 0 {
		return nil, errors.New("no pprof profiles found under pprof/ in the zip")
	}
	sort.Slice(profs, func(i, j int) bool { return profs[i].Name < profs[j].Name })
	b.Profiles = profs
	return b, nil
}

func findSibling(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func sampleTypeStrings(p *profile.Profile) []string {
	out := make([]string, 0, len(p.SampleType))
	for _, st := range p.SampleType {
		out = append(out, st.Type+"/"+st.Unit)
	}
	return out
}

func valueOr[T any](v *T, f func(*T) string) string {
	if v == nil {
		return ""
	}
	return f(v)
}

func profileDurationSec(p *profile.Profile) float64 {
	if p.DurationNanos > 0 {
		return float64(p.DurationNanos) / 1e9
	}
	if p.Period > 0 {
		return float64(len(p.Sample)) * (float64(p.Period) / 1e9)
	}
	return 0
}

//
// Aggregations (Top + Flame)
//

type TopRow struct {
	Func        string  `json:"func"`
	File        string  `json:"file"`
	Flat        int64   `json:"flat"`
	Cum         int64   `json:"cum"`
	FlatPercent float64 `json:"flatPct"`
	CumPercent  float64 `json:"cumPct"`
}

func buildTop(p *profile.Profile, valueIndex int) ([]TopRow, error) {
	if valueIndex < 0 || valueIndex >= len(p.SampleType) {
		valueIndex = 0
	}
	flat := map[uint64]int64{}
	cum := map[uint64]int64{}
	funcMeta := map[uint64]struct {
		name string
		file string
	}{}

	total := int64(0)
	for _, f := range p.Function {
		if f != nil {
			funcMeta[f.ID] = struct {
				name string
				file string
			}{name: f.Name, file: f.Filename}
		}
	}
	for _, s := range p.Sample {
		if s == nil || len(s.Value) <= valueIndex {
			continue
		}
		v := s.Value[valueIndex]
		total += v
		for _, loc := range s.Location {
			for _, line := range loc.Line {
				if line.Function != nil {
					cum[line.Function.ID] += v
				}
			}
		}
		if len(s.Location) > 0 {
			leaf := s.Location[0]
			if len(leaf.Line) > 0 && leaf.Line[0].Function != nil {
				flat[leaf.Line[0].Function.ID] += v
			}
		}
	}
	rows := []TopRow{}
	for fid, fv := range flat {
		mv := funcMeta[fid]
		cv := cum[fid]
		tr := TopRow{Func: mv.name, File: mv.file, Flat: fv, Cum: cv}
		if total > 0 {
			tr.FlatPercent = float64(fv) * 100 / float64(total)
			tr.CumPercent = float64(cv) * 100 / float64(total)
		}
		rows = append(rows, tr)
	}
	for fid, cv := range cum {
		if _, ok := flat[fid]; ok {
			continue
		}
		mv := funcMeta[fid]
		tr := TopRow{Func: mv.name, File: mv.file, Flat: 0, Cum: cv}
		if total > 0 {
			tr.CumPercent = float64(cv) * 100 / float64(total)
		}
		rows = append(rows, tr)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Flat == rows[j].Flat {
			return rows[i].Cum > rows[j].Cum
		}
		return rows[i].Flat > rows[j].Flat
	})
	return rows, nil
}

type FlameNode struct {
	Name     string       `json:"name"`
	Value    int64        `json:"value"`
	Children []*FlameNode `json:"children,omitempty"`
}

func buildFlame(p *profile.Profile, valueIndex int) (*FlameNode, error) {
	if valueIndex < 0 || valueIndex >= len(p.SampleType) {
		valueIndex = 0
	}
	root := &FlameNode{Name: "root"}

	getChild := func(parent *FlameNode, name string) *FlameNode {
		for _, c := range parent.Children {
			if c.Name == name {
				return c
			}
		}
		n := &FlameNode{Name: name}
		parent.Children = append(parent.Children, n)
		return n
	}

	for _, s := range p.Sample {
		if s == nil || len(s.Value) <= valueIndex {
			continue
		}
		v := s.Value[valueIndex]
		cur := root
		for i := len(s.Location) - 1; i >= 0; i-- {
			loc := s.Location[i]
			fn := "anon"
			if len(loc.Line) > 0 && loc.Line[0].Function != nil && loc.Line[0].Function.Name != "" {
				fn = loc.Line[0].Function.Name
			}
			cur = getChild(cur, fn)
			cur.Value += v
		}
	}

	var sortRec func(n *FlameNode)
	sortRec = func(n *FlameNode) {
		for _, c := range n.Children {
			sortRec(c)
		}
		sort.Slice(n.Children, func(i, j int) bool { return n.Children[i].Value > n.Children[j].Value })
	}
	sortRec(root)
	return root, nil
}

//
// Native pprof UI (per-profile) via reverse proxy
//

// Native pprof UI (per-profile) via child process + reverse proxy
// Native pprof UI (per-profile) via child process on a chosen port + reverse proxy
func (s *Store) ensurePprofTarget(id string) (*url.URL, error) {
	// Cached?
	s.pprofMu.RLock()
	if u := s.pprofTargets[id]; u != nil {
		s.pprofMu.RUnlock()
		return u, nil
	}
	s.pprofMu.RUnlock()

	p, ok := s.GetProfile(id)
	if !ok {
		return nil, errors.New("profile not found")
	}

	// Always hand pprof a raw protobuf (handles single/double gzip cases).
	dec, _, err := detectAndDecompressAll(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	// Write to a temp file with .pb extension so pprof doesn't try to gunzip it again.
	tf, err := os.CreateTemp("", "coder-pprof-*.pb")
	if err != nil {
		return nil, err
	}
	if _, err := tf.Write(dec); err != nil {
		_ = tf.Close()
		_ = os.Remove(tf.Name())
		return nil, err
	}
	_ = tf.Close()

	// Pick a free local port ourselves.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.Remove(tf.Name())
		return nil, fmt.Errorf("port pick: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	targetStr := fmt.Sprintf("http://127.0.0.1:%d", port)
	targetURL, _ := url.Parse(targetStr)

	// Launch pprof: use ONLY "go tool pprof" and force "no browser".
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, "go", "tool", "pprof",
		"-no_browser",
		"-http="+fmt.Sprintf("127.0.0.1:%d", port),
		tf.Name(),
	)
	// Prevent pprof from auto-opening the browser (belt & suspenders).
	cmd.Env = append(os.Environ(),
		"PPROF_NO_BROWSER=1",
		"BROWSER=none",
	)
	if err := cmd.Start(); err != nil {
		cancel()
		_ = os.Remove(tf.Name())
		return nil, fmt.Errorf("start pprof: %w", err)
	}

	// Wait for the server to accept connections.
	deadline := time.Now().Add(8 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			cancel()
			_ = os.Remove(tf.Name())
			return nil, fmt.Errorf("pprof did not come up on %s in time", targetStr)
		}
		time.Sleep(150 * time.Millisecond)
	}

	// Cache and keep the child alive; clean up when it exits.
	s.pprofMu.Lock()
	s.pprofTargets[id] = targetURL
	s.pprofMu.Unlock()

	go func() {
		_ = cmd.Wait()
		_ = os.Remove(tf.Name())
		s.pprofMu.Lock()
		delete(s.pprofTargets, id)
		s.pprofMu.Unlock()
		cancel()
	}()

	return targetURL, nil
}

//
// HTTP
//

var store = NewStore()

func main() {
	// Require a zip path at startup.
	var (
		bundlePath = flag.String("bundle", "", "Path to Coder support bundle .zip (required)")
		addr       = flag.String("addr", "127.0.0.1:6969", "Listen address")
	)
	flag.Parse()
	if strings.TrimSpace(*bundlePath) == "" {
		log.Fatalf("missing -bundle=PATH.zip (required)")
	}
	// Require Graphviz 'dot' so pprof Graph view works.
	if _, err := exec.LookPath("dot"); err != nil {
		log.Fatalf("Graphviz 'dot' not found in PATH.\nInstall it and try again:\n  macOS:  brew install graphviz\n  Debian/Ubuntu:  sudo apt-get install graphviz\n  Fedora/RHEL:    sudo dnf install graphviz")
	}

	fi, err := os.Stat(*bundlePath)
	if err != nil {
		log.Fatalf("bundle: %v", err)
	}
	f, err := os.Open(*bundlePath)
	if err != nil {
		log.Fatalf("open bundle: %v", err)
	}
	defer f.Close()

	b, err := loadBundleFromZip(f, fi.Size(), *bundlePath)
	if err != nil {
		log.Fatalf("load bundle: %v", err)
	}
	store.AddBundle(b)

	r := mux.NewRouter()
	r.HandleFunc("/", serveIndex)
	r.HandleFunc("/app.js", serveJS)
	r.HandleFunc("/style.css", serveCSS)

	// Read-only JSON APIs
	r.HandleFunc("/api/bundles", handleListBundles).Methods("GET")
	r.HandleFunc("/api/bundles/{id}", handleGetBundle).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/summary", handleProfileSummary).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/top", handleProfileTop).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/flame", handleProfileFlame).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/raw", handleProfileRaw).Methods("GET")

	// Native pprof UI per profile: reverse-proxy to the embedded pprof web UI.
	r.PathPrefix("/pprof/{id}/").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]
		target, err := store.ensurePprofTarget(id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		prefix := "/pprof/" + id

		// Convenience: /pprof/{id}/ → /pprof/{id}/ui
		if r.URL.Path == prefix || r.URL.Path == prefix+"/" {
			http.Redirect(w, r, prefix+"/ui", http.StatusFound)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(target)

		// Trim our prefix so pprof sees /ui, /top, etc.
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}

		// Rewrite absolute redirects like "/ui" or "http://127.0.0.1:PORT/ui"
		proxy.ModifyResponse = func(resp *http.Response) error {
			// 1) Location header (redirects)
			if loc := resp.Header.Get("Location"); loc != "" {
				if strings.HasPrefix(loc, target.String()) {
					// http://127.0.0.1:PORT/...  ->  /pprof/{id}/...
					resp.Header.Set("Location", prefix+strings.TrimPrefix(loc, target.String()))
				} else if strings.HasPrefix(loc, "/") {
					// /ui -> /pprof/{id}/ui
					resp.Header.Set("Location", prefix+loc)
				}
			}

			// 2) HTML body: rewrite absolute links & base href
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "text/html") {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				_ = resp.Body.Close()

				abs := target.String() // e.g., http://127.0.0.1:58309
				fixed := body

				// root-absolute → prefixed
				fixed = bytes.ReplaceAll(fixed, []byte(`href="/`), []byte(`href="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`src="/`), []byte(`src="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`action="/`), []byte(`action="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`<base href="/`), []byte(`<base href="`+prefix+`/`))

				// full-absolute (with host:port) → prefixed
				fixed = bytes.ReplaceAll(fixed, []byte(`href="`+abs+`/`), []byte(`href="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`src="`+abs+`/`), []byte(`src="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`action="`+abs+`/`), []byte(`action="`+prefix+`/`))

				resp.Body = io.NopCloser(bytes.NewReader(fixed))
				resp.Header.Set("Content-Length", strconv.Itoa(len(fixed)))
			}
			return nil
		}

		// Make sure the proxy requests actually hit the child pprof
		origDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			origDirector(req)
			req.Host = target.Host // avoid mixed host headers
			// Preserve query; Path already trimmed above in r.URL.Path.
		}

		proxy.ServeHTTP(w, r)
	})

	log.Printf("Loaded bundle %q with %d profiles. Native pprof UI mounted at /pprof/{profileID}/", b.Name, len(b.Profiles))
	listenURL := *addr
	if !strings.HasPrefix(listenURL, "http://") && !strings.HasPrefix(listenURL, "https://") {
		listenURL = "http://" + listenURL
	}
	log.Printf("Listening on %s", listenURL)
	log.Fatal(http.ListenAndServe(*addr, withCORS(r)))
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(indexHTML)
}
func serveJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(appJS)
}
func serveCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(styleCSS)
}

func handleListBundles(w http.ResponseWriter, r *http.Request) {
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := []*Bundle{}
	for _, b := range store.bundles {
		out = append(out, &Bundle{
			ID: b.ID, Name: b.Name, Created: b.Created, Profiles: b.Profiles,
		})
	}
	writeJSON(w, out)
}

func handleGetBundle(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	b, ok := store.GetBundle(id)
	if !ok {
		http.Error(w, "bundle not found", http.StatusNotFound)
		return
	}
	writeJSON(w, b)
}

func handleProfileSummary(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	p, ok := store.GetProfile(id)
	if !ok {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}
	writeJSON(w, p)
}

func handleProfileTop(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	p, ok := store.GetProfile(id)
	if !ok {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}
	vi := 0
	if qs := r.URL.Query().Get("valueIndex"); qs != "" {
		if n, err := strconv.Atoi(qs); err == nil {
			vi = n
		}
	}
	rows, err := buildTop(p.Profile, vi)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, rows)
}

func handleProfileFlame(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	p, ok := store.GetProfile(id)
	if !ok {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}
	vi := 0
	if qs := r.URL.Query().Get("valueIndex"); qs != "" {
		if n, err := strconv.Atoi(qs); err == nil {
			vi = n
		}
	}
	root, err := buildFlame(p.Profile, vi)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, root)
}

func handleProfileRaw(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	p, ok := store.GetProfile(id)
	if !ok {
		http.Error(w, "profile not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(p.Name))
	_, _ = w.Write(p.Bytes)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
