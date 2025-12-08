package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/handlers"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/metrics"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/parser"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/store"
)

// Constants and configuration
const (
	maxBundleSize      = 10 << 30 // 10GB
	maxProfileSize     = 1 << 30  // 1GB
	maxConcurrentOps   = 10
	pprofTimeout       = 30 * time.Minute
	defaultListenAddr  = "127.0.0.1:6969"
	maxGzipLayers      = 5
	maxAgentLogBytes   = 2 << 20 // 2MB of log content rendered to avoid huge payloads
	agentLogPath       = "agent/logs.txt"
	grafanaProviderUID = "coder-provider"
	grafanaFolderUID   = "coder-dashboards"
)

// Metrics - initialized in main()
var appMetrics *metrics.Metrics

// Type aliases for models package
type (
	StoredProfile        = models.StoredProfile
	Bundle               = models.Bundle
	PrometheusSnapshot   = models.PrometheusSnapshot
	BundleLog            = models.BundleLog
	BundleMetadata       = models.BundleMetadata
	HealthStatus         = models.HealthStatus
	HealthComponent      = models.HealthComponent
	NetworkInfo          = models.NetworkInfo
	NetworkHealthSummary = models.NetworkHealthSummary
	NetworkUsageSummary  = models.NetworkUsageSummary
	NetworkRegionStatus  = models.NetworkRegionStatus
	NetworkInterfaceInfo = models.NetworkInterfaceInfo
	LoadResult           = models.LoadResult
	TimeSeriesPoint      = models.TimeSeriesPoint
	TopRow               = models.TopRow
	FlameNode            = models.FlameNode
	ComparisonResult     = models.ComparisonResult
	ComparisonDiffRow    = models.ComparisonDiffRow
	FlameDiffNode        = models.FlameDiffNode
)

// Parser function aliases
var (
	makeID = parser.MakeID
)

// validateBundlePath validates that a path points to a valid bundle file.
func validateBundlePath(path string) (string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid path: %w", err)
	}
	info, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("path not found: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("path is a directory, expected a file")
	}
	if !strings.HasSuffix(strings.ToLower(absPath), ".zip") {
		return "", fmt.Errorf("expected .zip file")
	}
	return absPath, nil
}

// HTTP Handlers
func withMetrics(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h(w, r)
		appMetrics.RequestDuration.WithLabelValues(name, r.Method).Observe(time.Since(start).Seconds())
	}
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

func serveLogsHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(logsHTML)
}

func serveLogsJS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	_, _ = w.Write(logsJS)
}

func serveCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(styleCSS)
}

func handlePrometheusStatus(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		bundle, ok := s.GetBundle(id)
		if !ok {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		inst := s.GetPrometheusInstance(id)
		writeJSON(w, map[string]any{
			"snapshots": bundle.Prometheus,
			"instance":  inst,
		})
	}
}

func handlePrometheusStart(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		inst, err := s.StartPrometheus(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, inst)
	}
}

func handlePrometheusStop(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		s.StopPrometheus(id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func handlePprofProxy(s *store.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		ctx := r.Context()
		target, err := s.EnsurePprofTarget(ctx, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}

		prefix := "/pprof/" + id

		// Redirect root to /ui
		if r.URL.Path == prefix || r.URL.Path == prefix+"/" {
			http.Redirect(w, r, prefix+"/ui", http.StatusFound)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(target)

		// Trim prefix
		r.URL.Path = strings.TrimPrefix(r.URL.Path, prefix)
		if r.URL.Path == "" {
			r.URL.Path = "/"
		}

		// Rewrite responses
		proxy.ModifyResponse = func(resp *http.Response) error {
			// Rewrite Location header
			if loc := resp.Header.Get("Location"); loc != "" {
				if strings.HasPrefix(loc, target.String()) {
					resp.Header.Set("Location", prefix+strings.TrimPrefix(loc, target.String()))
				} else if strings.HasPrefix(loc, "/") {
					resp.Header.Set("Location", prefix+loc)
				}
			}

			// Rewrite HTML content
			ct := resp.Header.Get("Content-Type")
			if strings.Contains(ct, "text/html") {
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					return err
				}
				_ = resp.Body.Close()

				abs := target.String()
				fixed := body

				// Rewrite URLs
				fixed = bytes.ReplaceAll(fixed, []byte(`href="/`), []byte(`href="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`src="/`), []byte(`src="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`action="/`), []byte(`action="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`<base href="/`), []byte(`<base href="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`href="`+abs+`/`), []byte(`href="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`src="`+abs+`/`), []byte(`src="`+prefix+`/`))
				fixed = bytes.ReplaceAll(fixed, []byte(`action="`+abs+`/`), []byte(`action="`+prefix+`/`))

				resp.Body = io.NopCloser(bytes.NewReader(fixed))
				resp.Header.Set("Content-Length", strconv.Itoa(len(fixed)))
			}
			return nil
		}

		// Update director
		origDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			origDirector(req)
			req.Host = target.Host
		}

		proxy.ServeHTTP(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// Embedded frontend files (these would normally be actual files)
var (
	//go:embed web/index.html
	indexHTML []byte
	//go:embed web/app.js
	appJS []byte
	//go:embed web/style.css
	styleCSS []byte
	//go:embed web/logs.html
	logsHTML []byte
	//go:embed web/logs.js
	logsJS []byte
	//go:embed web/dashboards/*.json
	grafanaDashboardsFS embed.FS
)

// Main function
func main() {
	// Initialize metrics
	appMetrics = metrics.New()

	// Setup logging
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	// Flags
	var (
		bundlePaths = flag.String("bundle", "", "Path to Coder support bundle .zip (can be comma-separated for multiple)")
		addr        = flag.String("addr", defaultListenAddr, "Listen address")
		metricsAddr = flag.String("metrics", "", "Metrics address (e.g., :9090)")
		verbose     = flag.Bool("verbose", false, "Enable verbose logging")
	)
	flag.Parse()

	if *verbose {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		}))
	}

	// Check for required tools
	checkBinary := func(name string, instructions map[string]string) {
		if _, err := exec.LookPath(name); err != nil {
			args := make([]any, 0, len(instructions)+1)
			args = append(args, slog.String("binary", name))
			for platform, cmd := range instructions {
				args = append(args, slog.String(platform, cmd))
			}
			logger.Error("required binary not found in PATH", args...)
			os.Exit(1)
		}
	}

	checkBinary("dot", map[string]string{
		"install_macos":   "brew install graphviz",
		"install_debian":  "sudo apt-get install graphviz",
		"install_fedora":  "sudo dnf install graphviz",
		"install_arch":    "sudo pacman -S graphviz",
		"install_windows": "choco install graphviz",
	})

	checkBinary("prometheus", map[string]string{
		"install_macos":   "brew install prometheus",
		"install_debian":  "sudo apt-get install prometheus",
		"install_fedora":  "sudo dnf install prometheus",
		"install_arch":    "sudo pacman -S prometheus",
		"install_windows": "choco install prometheus",
	})

	// Create store
	store := store.New(logger, grafanaDashboardsFS)
	if _, err := store.EnsureGrafanaBinary(); err != nil {
		logger.Error("required binary not found", slog.String("binary", "grafana-server/grafana"), slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer store.StopGrafana()

	// Setup context with signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Start cleanup goroutine
	go store.CleanupOldProfiles(ctx)

	// Load initial bundles if provided
	if *bundlePaths != "" {
		paths := strings.Split(*bundlePaths, ",")
		for _, path := range paths {
			path = strings.TrimSpace(path)

			validPath, err := validateBundlePath(path)
			if err != nil {
				logger.Error("invalid bundle path",
					slog.String("path", path),
					slog.String("error", err.Error()))
				os.Exit(1)
			}

			f, err := os.Open(validPath)
			if err != nil {
				logger.Error("failed to open bundle",
					slog.String("path", validPath),
					slog.String("error", err.Error()))
				os.Exit(1)
			}

			fi, err := f.Stat()
			if err != nil {
				f.Close()
				logger.Error("failed to stat bundle",
					slog.String("path", validPath),
					slog.String("error", err.Error()))
				os.Exit(1)
			}
			result := parser.LoadBundleFromZip(f, fi.Size(), validPath, func() { appMetrics.ProfilesAnalyzed.Inc() })
			f.Close()

			if result.Error != nil {
				logger.Error("failed to load bundle",
					slog.String("path", validPath),
					slog.String("error", result.Error.Error()))
				os.Exit(1)
			}

			if len(result.Warnings) > 0 {
				for _, warn := range result.Warnings {
					logger.Warn("bundle warning",
						slog.String("bundle", result.Bundle.Name),
						slog.String("warning", warn))
				}
			}

			store.AddBundle(result.Bundle)
			logger.Info("loaded bundle",
				slog.String("name", result.Bundle.Name),
				slog.Int("profiles", len(result.Bundle.Profiles)),
				slog.Int("warnings", len(result.Warnings)))
		}
	}

	// Setup routes
	r := mux.NewRouter()

	// Static files
	r.HandleFunc("/", serveIndex)
	r.HandleFunc("/app.js", serveJS)
	r.HandleFunc("/logs", serveLogsHTML)
	r.HandleFunc("/logs.js", serveLogsJS)
	r.HandleFunc("/style.css", serveCSS)

	// API endpoints
	r.HandleFunc("/api/bundles", withMetrics("list_bundles", handlers.ListBundles(store))).Methods("GET")
	r.HandleFunc("/api/bundles", withMetrics("upload_bundle", handlers.UploadBundle(store, maxBundleSize, func() { appMetrics.ProfilesAnalyzed.Inc() }))).Methods("POST")
	r.HandleFunc("/api/bundles/{id}", withMetrics("get_bundle", handlers.GetBundle(store))).Methods("GET")
	r.HandleFunc("/api/bundles/{id}/logs/agent", withMetrics("bundle_agent_logs", handlers.BundleAgentLogs(store, maxAgentLogBytes))).Methods("GET")
	r.HandleFunc("/api/bundles/{id}/prometheus", withMetrics("prometheus_status", handlePrometheusStatus(store))).Methods("GET")
	r.HandleFunc("/api/bundles/{id}/prometheus/start", withMetrics("prometheus_start", handlePrometheusStart(store))).Methods("POST")
	r.HandleFunc("/api/bundles/{id}/prometheus/stop", withMetrics("prometheus_stop", handlePrometheusStop(store))).Methods("POST")
	r.HandleFunc("/api/profiles/search", withMetrics("search_profiles", handlers.SearchProfiles(store))).Methods("GET")
	r.HandleFunc("/api/profiles/compare", withMetrics("compare_profiles", handlers.CompareProfiles(store))).Methods("GET")
	r.HandleFunc("/api/profiles/flamediff", withMetrics("flame_diff", handlers.FlameDiff(store))).Methods("GET")
	r.HandleFunc("/api/profiles/timeseries", withMetrics("time_series", handlers.TimeSeries(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/summary", withMetrics("profile_summary", handlers.ProfileSummary(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/top", withMetrics("profile_top", handlers.ProfileTop(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/flame", withMetrics("profile_flame", handlers.ProfileFlame(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/raw", withMetrics("profile_raw", handlers.ProfileRaw(store))).Methods("GET")

	// Native pprof UI
	r.PathPrefix("/pprof/{id}/").HandlerFunc(withMetrics("pprof_proxy", handlePprofProxy(store)))

	// Metrics endpoint
	if *metricsAddr != "" {
		go func() {
			logger.Info("starting metrics server", slog.String("addr", *metricsAddr))
			http.Handle("/metrics", promhttp.Handler())
			if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
				logger.Error("metrics server failed", slog.String("error", err.Error()))
			}
		}()
	}

	// Start main server
	listenURL := *addr
	if !strings.HasPrefix(listenURL, "http://") && !strings.HasPrefix(listenURL, "https://") {
		listenURL = "http://" + listenURL
	}

	logger.Info("starting server",
		slog.String("url", listenURL),
		slog.Int("bundles", len(store.GetAllBundles())))

	srv := &http.Server{
		Addr:    *addr,
		Handler: withCORS(r),
	}

	// Start server in goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("server failed", slog.String("error", err.Error()))
			cancel()
		}
	}()

	// Wait for shutdown
	<-ctx.Done()
	logger.Info("shutting down")
	store.StopAllPrometheus()

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", slog.String("error", err.Error()))
	}
}
