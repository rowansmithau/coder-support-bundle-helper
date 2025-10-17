package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/pprof/profile"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"
)

// Constants and configuration
const (
	maxBundleSize      = 10 << 30 // 10GB
	maxProfileSize     = 1 << 30  // 1GB
	maxConcurrentOps   = 10
	pprofTimeout       = 30 * time.Minute
	defaultListenAddr  = "127.0.0.1:6969"
	maxGzipLayers      = 5
	grafanaProviderUID = "coder-provider"
	grafanaFolderUID   = "coder-dashboards"
)

// Metrics
var (
	bundlesLoaded = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "coder_bundle_helper_bundles_loaded_total",
		Help: "Total number of bundles loaded",
	})
	profilesAnalyzed = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "coder_bundle_helper_profiles_analyzed_total",
		Help: "Total number of profiles analyzed",
	})
	activeProfiles = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "coder_bundle_helper_active_pprof_instances",
		Help: "Number of active pprof instances",
	})
	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "coder_bundle_helper_request_duration_seconds",
		Help:    "HTTP request duration in seconds",
		Buckets: prometheus.DefBuckets,
	}, []string{"handler", "method"})
)

func init() {
	prometheus.MustRegister(bundlesLoaded, profilesAnalyzed, activeProfiles, requestDuration)
}

// Data model
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
	BundleID      string            `json:"bundleId"`
	Group         string            `json:"group,omitempty"`
}

type Bundle struct {
	ID                 string                `json:"id"`
	Name               string                `json:"name"`
	Created            time.Time             `json:"created"`
	Profiles           []*StoredProfile      `json:"profiles"`
	Warnings           []string              `json:"warnings,omitempty"`
	Path               string                `json:"path"`
	Metadata           *BundleMetadata       `json:"metadata,omitempty"`
	Prometheus         []*PrometheusSnapshot `json:"prometheus,omitempty"`
	PrometheusURL      string                `json:"prometheusUrl,omitempty"`
	PrometheusGraphURL string                `json:"prometheusGraphUrl,omitempty"`
	GrafanaURL         string                `json:"grafanaUrl,omitempty"`
	GrafanaFolderURL   string                `json:"grafanaFolderUrl,omitempty"`
}

type PrometheusSnapshot struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Source    string    `json:"source"`
	Path      string    `json:"path"`
	Size      int       `json:"size"`
	CreatedAt time.Time `json:"createdAt"`
	Content   []byte    `json:"-"`
}

type BundleMetadata struct {
	DeploymentID      string          `json:"deploymentId,omitempty"`
	LicenseStatus     json.RawMessage `json:"licenseStatus,omitempty"`
	LicenseStatusRaw  string          `json:"licenseStatusRaw,omitempty"`
	LicenseValid      bool            `json:"licenseValid"`
	LicenseFound      bool            `json:"licenseFound"`
	TailnetBuildInfo  json.RawMessage `json:"tailnetBuildInfo,omitempty"`
	BuildInfo         json.RawMessage `json:"buildInfo,omitempty"`
	LicenseMatch      bool            `json:"licenseMatch"`
	LicenseMismatch   string          `json:"licenseMismatch,omitempty"`
	BuildInfoMatch    bool            `json:"buildInfoMatch"`
	BuildInfoMismatch string          `json:"buildInfoMismatch,omitempty"`
	Version           string          `json:"version,omitempty"`
	DashboardURL      string          `json:"dashboardUrl,omitempty"`
	HealthStatus      *HealthStatus   `json:"healthStatus,omitempty"`
	Network           *NetworkInfo    `json:"network,omitempty"`
}

type HealthStatus struct {
	Healthy    bool              `json:"healthy"`
	Severity   string            `json:"severity"`
	Warnings   []string          `json:"warnings,omitempty"`
	Components []HealthComponent `json:"components,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
	Timestamp  *time.Time        `json:"timestamp,omitempty"`
}

type HealthComponent struct {
	Name      string   `json:"name"`
	Healthy   bool     `json:"healthy"`
	Severity  string   `json:"severity,omitempty"`
	Messages  []string `json:"messages,omitempty"`
	Dismissed bool     `json:"dismissed,omitempty"`
}

type NetworkInfo struct {
	Health         *NetworkHealthSummary  `json:"health,omitempty"`
	Usage          *NetworkUsageSummary   `json:"usage,omitempty"`
	Warnings       []string               `json:"warnings,omitempty"`
	Errors         []string               `json:"errors,omitempty"`
	Regions        []NetworkRegionStatus  `json:"regions,omitempty"`
	Interfaces     []NetworkInterfaceInfo `json:"interfaces,omitempty"`
	HostnameSuffix string                 `json:"hostnameSuffix,omitempty"`
	NetcheckLogs   []string               `json:"netcheckLogs,omitempty"`
}

type NetworkHealthSummary struct {
	Healthy  bool   `json:"healthy"`
	Severity string `json:"severity,omitempty"`
	Message  string `json:"message,omitempty"`
}

type NetworkUsageSummary struct {
	UsesSTUN                  *bool   `json:"usesStun,omitempty"`
	UsesEmbeddedDERP          *bool   `json:"usesEmbeddedDerp,omitempty"`
	EmbeddedDERPRegion        string  `json:"embeddedDerpRegion,omitempty"`
	PreferredDERP             string  `json:"preferredDerp,omitempty"`
	DirectConnectionsDisabled *bool   `json:"directConnectionsDisabled,omitempty"`
	ForceWebsockets           *bool   `json:"forceWebsockets,omitempty"`
	WorkspaceProxy            *bool   `json:"workspaceProxy,omitempty"`
	WorkspaceProxyReason      string  `json:"workspaceProxyReason,omitempty"`
	UDP                       *bool   `json:"udp,omitempty"`
	IPv4                      *bool   `json:"ipv4,omitempty"`
	IPv6                      *bool   `json:"ipv6,omitempty"`
	IPv4CanSend               *bool   `json:"ipv4CanSend,omitempty"`
	IPv6CanSend               *bool   `json:"ipv6CanSend,omitempty"`
	OSHasIPv6                 *bool   `json:"osHasIpv6,omitempty"`
	ICMPv4                    *bool   `json:"icmpv4,omitempty"`
	MappingVariesByDestIP     *bool   `json:"mappingVariesByDestIp,omitempty"`
	HairPinning               *bool   `json:"hairPinning,omitempty"`
	UPnP                      *bool   `json:"upnp,omitempty"`
	PMP                       *bool   `json:"pmp,omitempty"`
	PCP                       *bool   `json:"pcp,omitempty"`
	CaptivePortal             *string `json:"captivePortal,omitempty"`
	GlobalV4                  string  `json:"globalV4,omitempty"`
	GlobalV6                  string  `json:"globalV6,omitempty"`
}

type NetworkRegionStatus struct {
	RegionID            int      `json:"regionId,omitempty"`
	Code                string   `json:"code,omitempty"`
	Name                string   `json:"name,omitempty"`
	Healthy             bool     `json:"healthy"`
	Severity            string   `json:"severity,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
	Errors              []string `json:"errors,omitempty"`
	UsesWebsocket       *bool    `json:"usesWebsocket,omitempty"`
	CanExchangeMessages *bool    `json:"canExchangeMessages,omitempty"`
	EmbeddedRelay       bool     `json:"embeddedRelay"`
	LatencyMS           *float64 `json:"latencyMs,omitempty"`
}

type NetworkInterfaceInfo struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	Addresses []string `json:"addresses,omitempty"`
}

type LoadResult struct {
	Bundle   *Bundle
	Warnings []string
	Error    error
}

type Store struct {
	mu       sync.RWMutex
	bundles  map[string]*Bundle
	profiles map[string]*StoredProfile
	logger   *slog.Logger

	// pprof backends (native UI), one per profile ID
	pprofMu      sync.RWMutex
	pprofTargets map[string]*pprofInstance

	// Semaphore for limiting concurrent operations
	semaphore chan struct{}

	promMu         sync.Mutex
	promInstances  map[string]*PrometheusInstance
	promBaseDir    string
	promBinary     string
	promGoCacheDir string
	promGoModDir   string

	grafMu        sync.Mutex
	grafInstance  *GrafanaInstance
	grafBaseDir   string
	grafBinary    string
	grafHome      string
	grafFolderURL string
}

type pprofInstance struct {
	URL       *url.URL
	Process   *exec.Cmd
	Cancel    context.CancelFunc
	TempFile  string
	CreatedAt time.Time
}

type PrometheusInstance struct {
	BundleID   string    `json:"bundleId"`
	URL        string    `json:"url"`
	Address    string    `json:"address"`
	StartedAt  time.Time `json:"startedAt"`
	cmd        *exec.Cmd
	dataDir    string
	cancel     context.CancelFunc
	done       chan struct{}
	RangeStart time.Time `json:"rangeStart"`
	RangeEnd   time.Time `json:"rangeEnd"`
	GraphURL   string    `json:"graphUrl"`
}

type GrafanaInstance struct {
	URL           string    `json:"url"`
	Address       string    `json:"address"`
	PrometheusURL string    `json:"prometheusUrl"`
	StartedAt     time.Time `json:"startedAt"`
	cmd           *exec.Cmd
	cancel        context.CancelFunc
	done          chan struct{}
	baseDir       string
}

func NewStore(logger *slog.Logger) *Store {
	promBase := filepath.Join(os.TempDir(), "coder-support-prom")
	_ = os.MkdirAll(promBase, 0o755)
	promGoCache := filepath.Join(promBase, "gocache")
	promGoMod := filepath.Join(promBase, "gomodcache")
	_ = os.MkdirAll(promGoCache, 0o755)
	_ = os.MkdirAll(promGoMod, 0o755)

	grafBase := filepath.Join(os.TempDir(), "coder-support-grafana")
	_ = os.MkdirAll(grafBase, 0o755)

	return &Store{
		bundles:        make(map[string]*Bundle),
		profiles:       make(map[string]*StoredProfile),
		pprofTargets:   make(map[string]*pprofInstance),
		semaphore:      make(chan struct{}, maxConcurrentOps),
		logger:         logger,
		promInstances:  make(map[string]*PrometheusInstance),
		promBaseDir:    promBase,
		promGoCacheDir: promGoCache,
		promGoModDir:   promGoMod,
		grafBaseDir:    grafBase,
	}
}

func (s *Store) AddBundle(b *Bundle) {
	s.StopPrometheus(b.ID)

	s.grafMu.Lock()
	currentGrafURL := ""
	currentGrafFolder := ""
	if s.grafInstance != nil {
		currentGrafURL = s.grafInstance.URL
	}
	if s.grafFolderURL != "" {
		currentGrafFolder = s.grafFolderURL
	}
	s.grafMu.Unlock()

	s.mu.Lock()

	if existing, ok := s.bundles[b.ID]; ok {
		for _, p := range existing.Profiles {
			delete(s.profiles, p.ID)
		}
	}
	s.bundles[b.ID] = b
	b.GrafanaURL = currentGrafURL
	b.GrafanaFolderURL = currentGrafFolder
	for _, p := range b.Profiles {
		p.BundleID = b.ID
		s.profiles[p.ID] = p
	}
	bundlesLoaded.Inc()
	s.logger.Info("bundle added",
		slog.String("id", b.ID),
		slog.String("name", b.Name),
		slog.Int("profiles", len(b.Profiles)))
	shouldStart := len(b.Prometheus) > 0
	bundleID := b.ID
	s.mu.Unlock()

	if shouldStart {
		go func() {
			inst, err := s.StartPrometheus(context.Background(), bundleID)
			if err != nil {
				s.logger.Warn("auto start prometheus failed",
					slog.String("bundle", bundleID),
					slog.String("error", err.Error()))
				return
			}
			s.logger.Info("prometheus auto-started",
				slog.String("bundle", bundleID),
				slog.String("url", inst.URL))
		}()
	}
}

func (s *Store) setGrafanaLinks(baseURL, folderURL string) {
	s.mu.Lock()
	for _, bundle := range s.bundles {
		bundle.GrafanaURL = baseURL
		bundle.GrafanaFolderURL = folderURL
	}
	s.mu.Unlock()
}

func (s *Store) GetBundle(id string) (*Bundle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bundles[id]
	return b, ok
}

func (s *Store) GetAllBundles() []*Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Bundle, 0, len(s.bundles))
	for _, b := range s.bundles {
		result = append(result, b)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Created.After(result[j].Created)
	})
	return result
}

func (s *Store) GetProfile(id string) (*StoredProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	return p, ok
}

func (s *Store) SearchProfiles(query string) []*StoredProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if query == "" {
		result := make([]*StoredProfile, 0, len(s.profiles))
		for _, p := range s.profiles {
			result = append(result, p)
		}
		return result
	}

	// Case-insensitive regex search
	re, err := regexp.Compile("(?i)" + regexp.QuoteMeta(query))
	if err != nil {
		return nil
	}

	var result []*StoredProfile
	for _, p := range s.profiles {
		if re.MatchString(p.Name) || re.MatchString(p.Path) {
			result = append(result, p)
		}
	}
	return result
}

func (s *Store) CleanupOldProfiles(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.pprofMu.Lock()
			now := time.Now()
			for id, inst := range s.pprofTargets {
				if now.Sub(inst.CreatedAt) > pprofTimeout {
					s.logger.Info("cleaning up old pprof instance", slog.String("id", id))
					inst.Cancel()
					if inst.Process != nil && inst.Process.Process != nil {
						_ = inst.Process.Process.Kill()
					}
					if inst.TempFile != "" {
						_ = os.Remove(inst.TempFile)
					}
					delete(s.pprofTargets, id)
					activeProfiles.Dec()
				}
			}
			s.pprofMu.Unlock()
		}
	}
}

func (s *Store) StartPrometheus(ctx context.Context, bundleID string) (*PrometheusInstance, error) {
	s.mu.RLock()
	bundle, ok := s.bundles[bundleID]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("bundle %q not found", bundleID)
	}
	if len(bundle.Prometheus) == 0 {
		return nil, fmt.Errorf("bundle %q does not contain prometheus metrics", bundleID)
	}

	s.promMu.Lock()
	defer s.promMu.Unlock()

	if inst, ok := s.promInstances[bundleID]; ok && inst.cmd != nil && inst.cmd.Process != nil {
		if _, err := s.ensureGrafana(inst.URL); err != nil {
			return nil, err
		}
		return inst, nil
	}

	baseDir := filepath.Join(s.promBaseDir, bundleID)
	dataDir := filepath.Join(baseDir, "data")
	if err := os.RemoveAll(baseDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reset prometheus dir: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create prometheus data dir: %w", err)
	}

	startRange, endRange, err := s.buildTSDBFromSnapshots(bundleID, bundle.Prometheus, dataDir)
	if err != nil {
		return nil, err
	}

	configPath := filepath.Join(baseDir, "prometheus.yml")
	configContent := []byte("global:\n  scrape_interval: 1m\nscrape_configs: []\n")
	if err := os.WriteFile(configPath, configContent, 0o644); err != nil {
		return nil, fmt.Errorf("write prometheus config: %w", err)
	}

	bin, err := s.ensurePrometheusBinary()
	if err != nil {
		return nil, err
	}

	addr, err := chooseFreeAddress()
	if err != nil {
		return nil, fmt.Errorf("allocate listen address: %w", err)
	}

	cmdCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(cmdCtx, bin,
		"--config.file", configPath,
		"--storage.tsdb.path", dataDir,
		"--web.listen-address", addr,
		"--storage.tsdb.retention.time=168h",
		"--log.level=warn",
	)
	cmd.Env = append(os.Environ(),
		"GOMODCACHE="+s.promGoModDir,
		"GOCACHE="+s.promGoCacheDir,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("prometheus stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("prometheus stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start prometheus: %w", err)
	}

	go s.streamCommandOutput(stdout, "prometheus", bundleID, "stdout")
	go s.streamCommandOutput(stderr, "prometheus", bundleID, "stderr")

	done := make(chan struct{})
	inst := &PrometheusInstance{
		BundleID:   bundleID,
		URL:        "http://" + addr,
		Address:    addr,
		StartedAt:  time.Now(),
		cmd:        cmd,
		dataDir:    baseDir,
		cancel:     cancel,
		done:       done,
		RangeStart: startRange,
		RangeEnd:   endRange,
	}
	inst.GraphURL = buildPrometheusGraphURL(inst.URL, startRange, endRange)

	s.promInstances[bundleID] = inst

	if _, err := s.ensureGrafana(inst.URL); err != nil {
		s.logger.Error("grafana failed to start",
			slog.String("bundle", bundleID),
			slog.String("error", err.Error()))
		s.stopPrometheusLocked(bundleID)
		return nil, err
	}

	s.mu.Lock()
	if stored, ok := s.bundles[bundleID]; ok {
		stored.PrometheusURL = inst.URL
		stored.PrometheusGraphURL = inst.GraphURL
	}
	s.mu.Unlock()

	go func(inst *PrometheusInstance) {
		err := cmd.Wait()
		if err != nil {
			s.logger.Error("prometheus exited", slog.String("bundle", bundleID), slog.String("error", err.Error()))
		}
		s.promMu.Lock()
		delete(s.promInstances, bundleID)
		var nextProm *PrometheusInstance
		for _, candidate := range s.promInstances {
			nextProm = candidate
			break
		}
		stopGrafana := len(s.promInstances) == 0
		s.promMu.Unlock()
		if stopGrafana {
			s.grafMu.Lock()
			s.stopGrafanaLocked()
			s.grafMu.Unlock()
		} else if nextProm != nil {
			s.grafMu.Lock()
			needsUpdate := s.grafInstance != nil && s.grafInstance.PrometheusURL == inst.URL
			s.grafMu.Unlock()
			if needsUpdate {
				if _, err := s.ensureGrafana(nextProm.URL); err != nil {
					s.logger.Warn("failed to retarget grafana",
						slog.String("from", inst.URL),
						slog.String("to", nextProm.URL),
						slog.String("error", err.Error()))
				}
			}
		}
		s.mu.Lock()
		if stored, ok := s.bundles[bundleID]; ok {
			stored.PrometheusURL = ""
			stored.PrometheusGraphURL = ""
		}
		s.mu.Unlock()
		close(done)
	}(inst)

	return inst, nil
}

func (s *Store) StopPrometheus(bundleID string) {
	s.promMu.Lock()
	s.stopPrometheusLocked(bundleID)
	s.promMu.Unlock()
}

func (s *Store) stopPrometheusLocked(bundleID string) {
	inst, ok := s.promInstances[bundleID]
	if !ok {
		return
	}
	if inst.cancel != nil {
		inst.cancel()
	}
	if inst.cmd != nil && inst.cmd.Process != nil {
		_ = inst.cmd.Process.Signal(syscall.SIGTERM)
		if inst.done != nil {
			select {
			case <-inst.done:
			case <-time.After(5 * time.Second):
				_ = inst.cmd.Process.Kill()
			}
		}
	}
	delete(s.promInstances, bundleID)
	var nextProm *PrometheusInstance
	for _, candidate := range s.promInstances {
		nextProm = candidate
		break
	}
	stopGrafana := len(s.promInstances) == 0
	s.mu.Lock()
	if stored, ok := s.bundles[bundleID]; ok {
		stored.PrometheusURL = ""
		stored.PrometheusGraphURL = ""
	}
	s.mu.Unlock()
	if stopGrafana {
		s.grafMu.Lock()
		s.stopGrafanaLocked()
		s.grafMu.Unlock()
	} else if nextProm != nil {
		s.grafMu.Lock()
		needsUpdate := s.grafInstance != nil && s.grafInstance.PrometheusURL == inst.URL
		s.grafMu.Unlock()
		if needsUpdate {
			if _, err := s.ensureGrafana(nextProm.URL); err != nil {
				s.logger.Warn("failed to retarget grafana",
					slog.String("from", inst.URL),
					slog.String("to", nextProm.URL),
					slog.String("error", err.Error()))
			}
		}
	}
}

func (s *Store) ensurePrometheusBinary() (string, error) {
	if s.promBinary != "" {
		if _, err := os.Stat(s.promBinary); err == nil {
			return s.promBinary, nil
		}
	}

	bin, err := exec.LookPath("prometheus")
	if err != nil {
		return "", fmt.Errorf("prometheus binary not found: %w", err)
	}
	s.promBinary = bin
	return bin, nil
}

func (s *Store) writeGrafanaDashboards(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	files, err := fs.Glob(grafanaDashboardsFS, "web/dashboards/*.json")
	if err != nil {
		return err
	}
	for _, name := range files {
		data, err := grafanaDashboardsFS.ReadFile(name)
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, filepath.Base(name))
		if err := os.WriteFile(dest, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ensureGrafanaBinary() (string, error) {
	if s.grafBinary != "" {
		if _, err := os.Stat(s.grafBinary); err == nil {
			return s.grafBinary, nil
		}
	}

	envHome := strings.TrimSpace(os.Getenv("GF_PATHS_HOME"))
	if envHome != "" {
		if info, err := os.Stat(filepath.Join(envHome, "conf", "defaults.ini")); err == nil && !info.IsDir() {
			s.grafHome = envHome
		} else if s.logger != nil {
			s.logger.Warn("GF_PATHS_HOME does not look like a Grafana installation",
				slog.String("path", envHome))
		}
	}

	var lastErr error
	paths := make([]string, 0, 4)
	for _, name := range []string{"grafana", "grafana-server"} {
		if bin, err := exec.LookPath(name); err == nil {
			paths = append(paths, bin)
		} else {
			lastErr = err
		}
	}
	paths = append(paths,
		"/opt/homebrew/bin/grafana",
		"/usr/local/bin/grafana",
	)

	for _, bin := range paths {
		if bin == "" {
			continue
		}
		if _, err := os.Stat(bin); err != nil {
			continue
		}
		s.grafBinary = bin
		if s.grafHome == "" {
			home, detectErr := detectGrafanaHome(bin)
			if detectErr != nil {
				lastErr = detectErr
				continue
			}
			s.grafHome = home
		}
		return bin, nil
	}

	if lastErr != nil {
		return "", fmt.Errorf("grafana binary not found: %w", lastErr)
	}
	return "", fmt.Errorf("grafana binary not found: install grafana (brew install grafana | sudo apt-get install grafana | sudo dnf install grafana | choco install grafana)")
}

func detectGrafanaHome(bin string) (string, error) {
	resolved := bin
	if target, err := filepath.EvalSymlinks(bin); err == nil && target != "" {
		resolved = target
	}

	addCandidate := func(list *[]string, seen map[string]struct{}, path string) {
		if path == "" {
			return
		}
		clean := filepath.Clean(path)
		if clean == "." || clean == string(filepath.Separator) {
			return
		}
		if _, ok := seen[clean]; ok {
			return
		}
		seen[clean] = struct{}{}
		*list = append(*list, clean)
	}

	binDir := filepath.Dir(resolved)
	seen := make(map[string]struct{})
	candidates := make([]string, 0, 8)
	addCandidate(&candidates, seen, filepath.Join(binDir, ".."))
	root := filepath.Dir(binDir)
	addCandidate(&candidates, seen, filepath.Join(root, "share", "grafana"))
	addCandidate(&candidates, seen, filepath.Join(root, "lib", "grafana"))
	addCandidate(&candidates, seen, filepath.Join(root, "grafana"))
	addCandidate(&candidates, seen, filepath.Join(binDir, "..", ".."))

	for _, known := range []string{
		"/usr/share/grafana",
		"/usr/local/share/grafana",
		"/opt/homebrew/share/grafana",
	} {
		addCandidate(&candidates, seen, known)
	}

	for _, cand := range candidates {
		if info, err := os.Stat(filepath.Join(cand, "conf", "defaults.ini")); err == nil && !info.IsDir() {
			return cand, nil
		}
	}

	return "", fmt.Errorf("could not locate Grafana config defaults near %q", resolved)
}

func (s *Store) ensureGrafana(promURL string) (*GrafanaInstance, error) {
	if promURL == "" {
		return nil, fmt.Errorf("prometheus url required to start grafana")
	}
	s.grafMu.Lock()
	inst, err := s.ensureGrafanaLocked(promURL)
	s.grafMu.Unlock()
	if err != nil {
		return nil, err
	}
	s.setGrafanaLinks(inst.URL, s.grafFolderURL)
	return inst, nil
}

func (s *Store) ensureGrafanaLocked(promURL string) (*GrafanaInstance, error) {
	if s.grafInstance != nil && s.grafInstance.cmd != nil && s.grafInstance.cmd.Process != nil {
		if s.grafInstance.PrometheusURL == promURL {
			return s.grafInstance, nil
		}
		s.stopGrafanaLocked()
	}

	bin, err := s.ensureGrafanaBinary()
	if err != nil {
		return nil, err
	}

	baseDir := filepath.Join(s.grafBaseDir, "instance")
	if err := os.RemoveAll(baseDir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("reset grafana dir: %w", err)
	}

	dataDir := filepath.Join(baseDir, "data")
	logsDir := filepath.Join(baseDir, "logs")
	pluginsDir := filepath.Join(baseDir, "plugins")
	provisionDir := filepath.Join(baseDir, "provisioning")
	dashboardConfigDir := filepath.Join(provisionDir, "dashboards")
	dashboardContentDir := filepath.Join(baseDir, "dashboards")
	dataSourceDir := filepath.Join(provisionDir, "datasources")
	alertingDir := filepath.Join(provisionDir, "alerting")
	pluginProvDir := filepath.Join(provisionDir, "plugins")

	for _, dir := range []string{dataDir, logsDir, pluginsDir, dashboardConfigDir, dataSourceDir, alertingDir, pluginProvDir, dashboardContentDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create grafana dir %q: %w", dir, err)
		}
	}

	if err := s.writeGrafanaDashboards(dashboardContentDir); err != nil {
		return nil, fmt.Errorf("write grafana dashboards: %w", err)
	}

	datasourceConfig := fmt.Sprintf(`apiVersion: 1
datasources:
  - name: Prometheus
    uid: prometheus
    type: prometheus
    access: proxy
    url: %s
    isDefault: true
    editable: false
`, promURL)

	if err := os.WriteFile(filepath.Join(dataSourceDir, "datasource.yaml"), []byte(datasourceConfig), 0o644); err != nil {
		return nil, fmt.Errorf("write grafana datasource config: %w", err)
	}

	dashboardsConfig := fmt.Sprintf(`apiVersion: 1
providers:
  - name: Coder Dashboards
    uid: %s
    orgId: 1
    folder: Coder
    folderUid: %s
    type: file
    disableDeletion: false
    editable: true
    allowUiUpdates: true
    updateIntervalSeconds: 30
    options:
      path: %q
`, grafanaProviderUID, grafanaFolderUID, dashboardContentDir)

	if err := os.WriteFile(filepath.Join(dashboardConfigDir, "coder.yaml"), []byte(dashboardsConfig), 0o644); err != nil {
		return nil, fmt.Errorf("write grafana dashboards config: %w", err)
	}

	addr, err := chooseFreeAddress()
	if err != nil {
		return nil, fmt.Errorf("allocate grafana address: %w", err)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid grafana address %q: %w", addr, err)
	}

	cmdCtx, cancel := context.WithCancel(context.Background())
	args := make([]string, 0, 4)
	baseName := strings.ToLower(filepath.Base(bin))
	baseName = strings.TrimSuffix(baseName, ".exe")
	if baseName == "grafana" {
		args = append(args, "server")
	}
	if s.grafHome != "" {
		args = append(args, "--homepath", s.grafHome)
	}
	cmd := exec.CommandContext(cmdCtx, bin, args...)
	if s.grafHome != "" {
		cmd.Dir = s.grafHome
	}
	env := append(os.Environ(),
		"GF_SERVER_HTTP_ADDR="+host,
		"GF_SERVER_HTTP_PORT="+port,
		"GF_SERVER_DOMAIN="+host,
		"GF_AUTH_ANONYMOUS_ENABLED=true",
		"GF_AUTH_ANONYMOUS_ORG_ROLE=Editor",
		"GF_USERS_EDITORS_CAN_ADMIN=true",
		"GF_USERS_ALLOW_SIGN_UP=false",
		"GF_USERS_AUTO_ASSIGN_ORG=true",
		"GF_USERS_AUTO_ASSIGN_ORG_ROLE=Editor",
		"GF_ANALYTICS_REPORTING_ENABLED=false",
		"GF_ANALYTICS_CHECK_FOR_UPDATES=false",
		"GF_LOG_MODE=console",
		"GF_LOG_CONSOLE_LEVEL=error",
		"GF_PATHS_DATA="+dataDir,
		"GF_PATHS_LOGS="+logsDir,
		"GF_PATHS_PLUGINS="+pluginsDir,
		"GF_PATHS_PROVISIONING="+provisionDir,
	)
	if s.grafHome != "" {
		env = append(env, "GF_PATHS_HOME="+s.grafHome)
	}
	cmd.Env = env

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("grafana stdout: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("grafana stderr: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start grafana: %w", err)
	}

	go s.streamCommandOutput(stdout, "grafana", "global", "stdout")
	go s.streamCommandOutput(stderr, "grafana", "global", "stderr")

	done := make(chan struct{})
	inst := &GrafanaInstance{
		URL:           "http://" + addr,
		Address:       addr,
		PrometheusURL: promURL,
		StartedAt:     time.Now(),
		cmd:           cmd,
		cancel:        cancel,
		done:          done,
		baseDir:       baseDir,
	}

	folderURL := ""
	if inst.URL != "" {
		base := strings.TrimSuffix(inst.URL, "/")
		folderURL = base + "/dashboards/f/" + grafanaFolderUID + "?orgId=1"
	}
	s.grafFolderURL = folderURL

	s.grafInstance = inst

	go func(current *GrafanaInstance) {
		err := cmd.Wait()
		if err != nil {
			s.logger.Error("grafana exited", slog.String("error", err.Error()))
		}
		s.grafMu.Lock()
		if s.grafInstance == current {
			s.grafInstance = nil
			s.grafFolderURL = ""
		}
		s.grafMu.Unlock()
		s.setGrafanaLinks("", "")
		close(done)
		_ = os.RemoveAll(baseDir)
	}(inst)

	s.logger.Info("grafana started",
		slog.String("url", inst.URL),
		slog.String("prometheus", promURL))

	return inst, nil
}

func (s *Store) stopGrafanaLocked() {
	if s.grafInstance == nil {
		return
	}
	inst := s.grafInstance
	if inst.cancel != nil {
		inst.cancel()
	}
	if inst.cmd != nil && inst.cmd.Process != nil {
		_ = inst.cmd.Process.Signal(syscall.SIGTERM)
		if inst.done != nil {
			select {
			case <-inst.done:
			case <-time.After(5 * time.Second):
				_ = inst.cmd.Process.Kill()
			}
		}
	}
	s.grafInstance = nil
	s.grafFolderURL = ""
	s.setGrafanaLinks("", "")
	if inst.baseDir != "" {
		_ = os.RemoveAll(inst.baseDir)
	}
}

func (s *Store) StopGrafana() {
	s.grafMu.Lock()
	s.stopGrafanaLocked()
	s.grafMu.Unlock()
}

func (s *Store) buildTSDBFromSnapshots(bundleID string, snapshots []*PrometheusSnapshot, dataDir string) (time.Time, time.Time, error) {
	if len(snapshots) == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("bundle %q does not contain prometheus metrics", bundleID)
	}

	entries, err := os.ReadDir(dataDir)
	if err == nil {
		for _, entry := range entries {
			_ = os.RemoveAll(filepath.Join(dataDir, entry.Name()))
		}
	}

	writer, err := tsdb.NewBlockWriter(promslog.NewNopLogger(), dataDir, int64(4*time.Hour/time.Millisecond))
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("create block writer: %w", err)
	}
	defer writer.Close()

	ctx := context.Background()
	app := writer.Appender(ctx)
	totalSamples := 0
	baseNow := time.Now().UnixMilli()
	minTs := int64(math.MaxInt64)
	maxTs := int64(math.MinInt64)

	for idx, snap := range snapshots {
		content, _, err := detectAndDecompressAll(snap.Content)
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("decompress metrics %s: %w", snap.Name, err)
		}
		if len(content) == 0 {
			continue
		}
		if content[len(content)-1] != '\n' {
			content = append(content, '\n')
		}
		parser := expfmt.NewTextParser(model.LegacyValidation)
		families, err := parser.TextToMetricFamilies(bytes.NewReader(content))
		if err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("parse metrics %s: %w", snap.Name, err)
		}

		baseTs := baseNow + int64(idx*1000)
		if !snap.CreatedAt.IsZero() {
			baseTs = snap.CreatedAt.UnixMilli()
		}

		extraBase := map[string]string{
			"bundle_id": bundleID,
		}
		if snap.Source != "" {
			extraBase["snapshot_source"] = snap.Source
		}
		if snap.Name != "" {
			extraBase["snapshot_name"] = snap.Name
		}

		for name, fam := range families {
			for _, metric := range fam.Metric {
				ts := baseTs
				if metric.TimestampMs != nil && metric.GetTimestampMs() > 0 {
					ts = metric.GetTimestampMs()
				}
				count, err := s.appendMetricSamples(app, name, fam.GetType(), metric, ts, extraBase)
				if err != nil {
					return time.Time{}, time.Time{}, fmt.Errorf("append metric %s: %w", name, err)
				}
				totalSamples += count
				if count > 0 {
					if ts < minTs {
						minTs = ts
					}
					if ts > maxTs {
						maxTs = ts
					}
				}
			}
		}
	}

	if totalSamples == 0 {
		return time.Time{}, time.Time{}, fmt.Errorf("no samples generated from prometheus metrics")
	}

	if err := app.Commit(); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("commit prometheus samples: %w", err)
	}
	if _, err := writer.Flush(ctx); err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("flush prometheus block: %w", err)
	}
	if minTs == math.MaxInt64 || maxTs == math.MinInt64 {
		return time.Time{}, time.Time{}, fmt.Errorf("no timestamps generated from prometheus metrics")
	}
	return time.UnixMilli(minTs).UTC(), time.UnixMilli(maxTs).UTC(), nil
}

func (s *Store) appendMetricSamples(app storage.Appender, name string, famType dto.MetricType, metric *dto.Metric, ts int64, extra map[string]string) (int, error) {
	samples := 0
	switch famType {
	case dto.MetricType_COUNTER:
		if metric.GetCounter() == nil {
			return 0, nil
		}
		count, err := addSample(app, metric, name, metric.GetCounter().GetValue(), ts, extra)
		samples += count
		return samples, err
	case dto.MetricType_GAUGE:
		if metric.GetGauge() == nil {
			return 0, nil
		}
		count, err := addSample(app, metric, name, metric.GetGauge().GetValue(), ts, extra)
		samples += count
		return samples, err
	case dto.MetricType_UNTYPED:
		if metric.GetUntyped() == nil {
			return 0, nil
		}
		count, err := addSample(app, metric, name, metric.GetUntyped().GetValue(), ts, extra)
		samples += count
		return samples, err
	case dto.MetricType_SUMMARY:
		summary := metric.GetSummary()
		if summary == nil {
			return 0, nil
		}
		for _, q := range summary.Quantile {
			extraQ := cloneExtra(extra)
			extraQ["quantile"] = formatFloat(q.GetQuantile())
			count, err := addSample(app, metric, name, q.GetValue(), ts, extraQ)
			samples += count
			if err != nil {
				return samples, err
			}
		}
		if summary.SampleSum != nil {
			count, err := addSample(app, metric, name+"_sum", summary.GetSampleSum(), ts, extra)
			samples += count
			if err != nil {
				return samples, err
			}
		}
		if summary.SampleCount != nil {
			count, err := addSample(app, metric, name+"_count", float64(summary.GetSampleCount()), ts, extra)
			samples += count
			if err != nil {
				return samples, err
			}
		}
		return samples, nil
	case dto.MetricType_HISTOGRAM, dto.MetricType_GAUGE_HISTOGRAM:
		hist := metric.GetHistogram()
		if hist == nil {
			return 0, nil
		}
		for _, bucket := range hist.Bucket {
			extraB := cloneExtra(extra)
			extraB["le"] = formatLE(bucket.GetUpperBound())
			count, err := addSample(app, metric, name+"_bucket", float64(bucket.GetCumulativeCount()), ts, extraB)
			samples += count
			if err != nil {
				return samples, err
			}
		}
		extraInf := cloneExtra(extra)
		extraInf["le"] = "+Inf"
		count, err := addSample(app, metric, name+"_bucket", float64(hist.GetSampleCount()), ts, extraInf)
		samples += count
		if err != nil {
			return samples, err
		}
		if hist.SampleSum != nil {
			count, err := addSample(app, metric, name+"_sum", hist.GetSampleSum(), ts, extra)
			samples += count
			if err != nil {
				return samples, err
			}
		}
		if hist.SampleCount != nil {
			count, err := addSample(app, metric, name+"_count", float64(hist.GetSampleCount()), ts, extra)
			samples += count
			if err != nil {
				return samples, err
			}
		}
		return samples, nil
	default:
		// Treat unknown types as gauge if possible.
		if metric.GetGauge() != nil {
			count, err := addSample(app, metric, name, metric.GetGauge().GetValue(), ts, extra)
			samples += count
			return samples, err
		}
		if metric.GetUntyped() != nil {
			count, err := addSample(app, metric, name, metric.GetUntyped().GetValue(), ts, extra)
			samples += count
			return samples, err
		}
		s.logger.Warn("unsupported metric type", slog.String("name", name), slog.Any("type", famType))
	}
	return samples, nil
}

func addSample(app storage.Appender, metric *dto.Metric, name string, value float64, ts int64, extra map[string]string) (int, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, nil
	}
	labelsMap := make(map[string]string, len(metric.Label)+1+len(extra))
	labelsMap["__name__"] = name
	for _, lp := range metric.Label {
		if lp.GetName() == "" {
			continue
		}
		labelsMap[lp.GetName()] = lp.GetValue()
	}
	for k, v := range extra {
		if v == "" {
			continue
		}
		labelsMap[k] = v
	}
	lset := labels.FromMap(labelsMap)
	if len(labelsMap) == 0 {
		return 0, nil
	}
	if _, err := app.Append(0, lset, ts, value); err != nil {
		return 0, err
	}
	return 1, nil
}

func cloneExtra(src map[string]string) map[string]string {
	if len(src) == 0 {
		return map[string]string{}
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func formatFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

func formatLE(v float64) string {
	if math.IsInf(v, +1) {
		return "+Inf"
	}
	return formatFloat(v)
}

func prometheusRangeString(d time.Duration) string {
	if d <= 0 {
		return "1h"
	}
	if d < time.Minute {
		return "1m"
	}
	if d < time.Hour {
		mins := int(math.Ceil(d.Minutes()))
		if mins < 1 {
			mins = 1
		}
		return fmt.Sprintf("%dm", mins)
	}
	if d < 24*time.Hour {
		hours := int(math.Ceil(d.Hours()))
		if hours < 1 {
			hours = 1
		}
		return fmt.Sprintf("%dh", hours)
	}
	days := int(math.Ceil(d.Hours() / 24))
	if days < 1 {
		days = 1
	}
	return fmt.Sprintf("%dd", days)
}

func buildPrometheusGraphURL(baseURL string, start, end time.Time) string {
	if baseURL == "" || start.IsZero() || end.IsZero() {
		return ""
	}
	if !end.After(start) {
		end = start.Add(time.Hour)
	}
	rangeStr := prometheusRangeString(end.Sub(start))
	endStr := end.UTC().Format("2006-01-02 15:04:05")
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	if parsed.Path == "" || parsed.Path == "/" {
		parsed.Path = "/graph"
	} else if !strings.HasSuffix(parsed.Path, "/graph") {
		parsed.Path = strings.TrimRight(parsed.Path, "/") + "/graph"
	}
	q := parsed.Query()
	q.Set("g0.range_input", rangeStr)
	q.Set("g0.end_input", endStr)
	if q.Get("g0.expr") == "" {
		q.Set("g0.expr", "")
	}
	if q.Get("g0.tab") == "" {
		q.Set("g0.tab", "0")
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func chooseFreeAddress() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr, nil
}

func (s *Store) streamCommandOutput(r io.Reader, component, identifier, stream string) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		fields := []any{
			slog.String("component", component),
			slog.String("id", identifier),
			slog.String("stream", stream),
			slog.String("line", line),
		}
		if component == "grafana" {
			s.logger.Info("process output", fields...)
		} else {
			s.logger.Debug("process output", fields...)
		}
	}
	if err := scanner.Err(); err != nil {
		s.logger.Warn("process stream error",
			slog.String("component", component),
			slog.String("id", identifier),
			slog.String("stream", stream),
			slog.String("error", err.Error()))
	}
}

// Time-series analysis
type TimeSeriesPoint struct {
	Timestamp time.Time        `json:"timestamp"`
	BundleID  string           `json:"bundleId"`
	ProfileID string           `json:"profileId"`
	Name      string           `json:"name"`
	Metrics   map[string]int64 `json:"metrics"`
}

func (s *Store) GetTimeSeries(functionName string) []TimeSeriesPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var points []TimeSeriesPoint

	for _, bundle := range s.bundles {
		for _, profile := range bundle.Profiles {
			if profile.Profile == nil {
				continue
			}

			// Get metrics for the specified function
			metrics := make(map[string]int64)
			for _, sample := range profile.Profile.Sample {
				for _, loc := range sample.Location {
					for _, line := range loc.Line {
						if line.Function != nil &&
							(functionName == "" || strings.Contains(line.Function.Name, functionName)) {
							for i, st := range profile.Profile.SampleType {
								if i < len(sample.Value) {
									key := st.Type + "/" + st.Unit
									metrics[key] += sample.Value[i]
								}
							}
						}
					}
				}
			}

			if len(metrics) > 0 {
				points = append(points, TimeSeriesPoint{
					Timestamp: bundle.Created,
					BundleID:  bundle.ID,
					ProfileID: profile.ID,
					Name:      profile.Name,
					Metrics:   metrics,
				})
			}
		}
	}

	// Sort by timestamp
	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})

	return points
}

// Utilities
func makeID(parts ...string) string {
	return strings.ReplaceAll(strings.ToLower(strings.Join(parts, "_")), " ", "-")
}

func detectAndDecompressAll(data []byte) ([]byte, int, error) {
	layers := 0
	out := data
	for len(out) >= 2 && out[0] == 0x1f && out[1] == 0x8b {
		if layers >= maxGzipLayers {
			return nil, layers, fmt.Errorf("too many gzip layers (>%d)", maxGzipLayers)
		}
		gr, err := gzip.NewReader(bytes.NewReader(out))
		if err != nil {
			return nil, layers, err
		}
		dec, err := io.ReadAll(gr)
		_ = gr.Close()
		if err != nil {
			return nil, layers, err
		}
		if len(dec) > maxProfileSize {
			return nil, layers, fmt.Errorf("decompressed data exceeds max profile size (%d bytes)", maxProfileSize)
		}
		out = dec
		layers++
	}
	return out, layers, nil
}

func parseProfile(name string, data []byte) (*profile.Profile, error) {
	if len(data) > maxProfileSize {
		return nil, fmt.Errorf("profile %s too large: %d bytes (max: %d)", name, len(data), maxProfileSize)
	}

	buf, _, err := detectAndDecompressAll(data)
	if err != nil {
		return nil, fmt.Errorf("decompress %s: %w", name, err)
	}
	if len(buf) > maxProfileSize {
		return nil, fmt.Errorf("profile %s too large after decompression: %d bytes (max: %d)", name, len(buf), maxProfileSize)
	}
	p, err := profile.Parse(bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("parse profile %s: %w", name, err)
	}
	return p, nil
}

func validateBundlePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", errors.New("bundle path is required")
	}

	// Resolve to absolute path
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("invalid bundle path: %w", err)
	}

	// Check if file exists
	fi, err := os.Stat(absPath)
	if err != nil {
		return "", fmt.Errorf("bundle file not found: %w", err)
	}

	// Check file size
	if fi.Size() > maxBundleSize {
		return "", fmt.Errorf("bundle too large: %d bytes (max: %d)", fi.Size(), maxBundleSize)
	}

	// Check if it's a regular file
	if !fi.Mode().IsRegular() {
		return "", errors.New("bundle path must be a regular file")
	}

	// Basic zip validation
	if !strings.HasSuffix(strings.ToLower(absPath), ".zip") {
		return "", errors.New("bundle must be a .zip file")
	}

	return absPath, nil
}

func loadBundleFromZip(r io.ReaderAt, size int64, filename string) *LoadResult {
	result := &LoadResult{
		Warnings: []string{},
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		result.Error = fmt.Errorf("failed to open zip: %w", err)
		return result
	}

	now := time.Now().UTC()
	b := &Bundle{
		ID:       makeID(filepath.Base(filename), fmt.Sprintf("%d", now.UnixNano())),
		Name:     filepath.Base(filename),
		Created:  now,
		Path:     filename,
		Warnings: []string{},
		Metadata: &BundleMetadata{},
	}

	// Parse metadata files
	if captured := parseBundleMetadata(zr, b.Metadata, &result.Warnings); captured != nil {
		b.Created = *captured
	}

	var (
		profs     []*StoredProfile
		promSnaps []*PrometheusSnapshot
	)
	for _, f := range zr.File {
		lower := strings.ToLower(f.Name)
		if strings.HasSuffix(lower, "prometheus.txt") {
			rc, err := f.Open()
			if err != nil {
				warning := fmt.Sprintf("failed to open %s: %v", f.Name, err)
				result.Warnings = append(result.Warnings, warning)
				continue
			}
			content, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				warning := fmt.Sprintf("failed to read %s: %v", f.Name, err)
				result.Warnings = append(result.Warnings, warning)
				continue
			}

			source := "unknown"
			switch {
			case strings.HasPrefix(lower, "agent/"):
				source = "agent"
			case strings.HasPrefix(lower, "deployment/"):
				source = "deployment"
			}

			promSnaps = append(promSnaps, &PrometheusSnapshot{
				ID:        makeID(b.ID, f.Name),
				Name:      filepath.Base(f.Name),
				Source:    source,
				Path:      f.Name,
				Size:      len(content),
				CreatedAt: b.Created,
				Content:   content,
			})
			continue
		}

		if !strings.HasPrefix(f.Name, "pprof/") {
			continue
		}
		if !(strings.HasSuffix(lower, ".pprof") ||
			strings.HasSuffix(lower, ".pprof.gz") ||
			strings.HasSuffix(lower, ".prof.gz") ||
			strings.HasSuffix(lower, ".pb.gz")) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			warning := fmt.Sprintf("failed to open %s: %v", f.Name, err)
			result.Warnings = append(result.Warnings, warning)
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			warning := fmt.Sprintf("failed to read %s: %v", f.Name, err)
			result.Warnings = append(result.Warnings, warning)
			continue
		}

		p, err := parseProfile(f.Name, content)
		if err != nil {
			warning := fmt.Sprintf("failed to parse %s: %v", f.Name, err)
			result.Warnings = append(result.Warnings, warning)
			continue
		}

		meta := map[string]string{}
		if cmdlineFile := findSibling(zr, "pprof/cmdline.txt"); cmdlineFile != nil {
			if rc2, err := cmdlineFile.Open(); err == nil {
				if bb, err := io.ReadAll(rc2); err == nil {
					meta["cmdline.txt"] = strings.TrimSpace(string(bb))
				}
				rc2.Close()
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
			Group:         profileGroupFromPath(f.Name),
		}
		profs = append(profs, sp)
		profilesAnalyzed.Inc()
	}

	if len(profs) == 0 {
		result.Warnings = append(result.Warnings, "No pprof profiles found under pprof/ in the zip")
		b.Profiles = []*StoredProfile{}
	} else {
		sort.Slice(profs, func(i, j int) bool { return profs[i].Name < profs[j].Name })
		b.Profiles = profs
	}
	b.Prometheus = promSnaps
	b.Warnings = result.Warnings
	result.Bundle = b

	return result
}

func parseBundleMetadata(zr *zip.Reader, metadata *BundleMetadata, warnings *[]string) *time.Time {
	var buildInfoRaw []byte
	var capturedAt *time.Time
	// Parse deployment/buildinfo.json
	if buildinfoFile := findSibling(zr, "deployment/buildinfo.json"); buildinfoFile != nil {
		if rc, err := buildinfoFile.Open(); err == nil {
			if content, err := io.ReadAll(rc); err == nil {
				content = bytes.TrimSpace(content)
				buildInfoRaw = append([]byte(nil), content...)
				if len(content) > 0 {
					metadata.BuildInfo = json.RawMessage(content)
				}
				var buildInfo map[string]interface{}
				if err := json.Unmarshal(content, &buildInfo); err == nil {
					// Extract deployment_id
					if deploymentID, ok := buildInfo["deployment_id"].(string); ok {
						metadata.DeploymentID = deploymentID
					}
					// Extract version
					if version, ok := buildInfo["version"].(string); ok {
						metadata.Version = version
					}
					// Also check for external_url
					if extURL, ok := buildInfo["external_url"].(string); ok && metadata.Version == "" {
						// Sometimes version is in external_url
						if strings.Contains(extURL, "/commit/") {
							parts := strings.Split(extURL, "/commit/")
							if len(parts) > 1 && len(parts[1]) >= 8 {
								metadata.Version = "commit:" + parts[1][:8] // First 8 chars of commit
							}
						}
					}
				} else {
					*warnings = append(*warnings, fmt.Sprintf("deployment/buildinfo.json is not valid JSON: %v", err))
				}
			}
			_ = rc.Close()
		}
	}

	// Parse license-status.txt
	if licenseFile := findSibling(zr, "license-status.txt"); licenseFile != nil {
		if rc, err := licenseFile.Open(); err == nil {
			if content, err := io.ReadAll(rc); err == nil {
				metadata.LicenseFound = true

				// Check if it's JSON or plain text
				trimmedContent := bytes.TrimSpace(content)
				metadata.LicenseStatusRaw = string(trimmedContent)
				if len(trimmedContent) > 0 {
					// Try to parse as JSON first
					if trimmedContent[0] == '{' || trimmedContent[0] == '[' {
						var licenseData map[string]interface{}
						if err := json.Unmarshal(trimmedContent, &licenseData); err == nil {
							metadata.LicenseStatus = json.RawMessage(trimmedContent)

							// Check if it has expected fields for a valid license
							if _, hasExtURL := licenseData["external_url"]; hasExtURL {
								metadata.LicenseValid = true
							}

							// Extract version and dashboard URL if available
							if v, ok := licenseData["version"].(string); ok && metadata.Version == "" {
								metadata.Version = v
							}
							if d, ok := licenseData["dashboard_url"].(string); ok {
								metadata.DashboardURL = d
							}
							if d, ok := licenseData["deployment_id"].(string); ok && metadata.DeploymentID == "" {
								metadata.DeploymentID = d
							}
						} else {
							// JSON parse failed but file looks like it should be JSON
							*warnings = append(*warnings, fmt.Sprintf("license-status.txt appears to be malformed JSON: %v", err))
							// Store the raw content anyway
							metadata.LicenseStatus = json.RawMessage(fmt.Sprintf(`{"error": "malformed", "raw": %q}`, string(trimmedContent)))
							metadata.LicenseValid = false
						}
					} else {
						// Plain text content - check if it's a table format or error message
						textContent := string(trimmedContent)

						// Check if it's a tabular format (like from Coder CLI)
						lines := strings.Split(textContent, "\n")
						if len(lines) >= 2 && strings.Contains(lines[0], "UUID") && strings.Contains(lines[0], "EXPIRES AT") {
							// Parse tabular license format
							// Header line: ID  UUID  UPLOADED AT  FEATURES  EXPIRES AT  TRIAL
							// Data line:    1  uuid  timestamp    features  timestamp   false

							licenseInfo := make(map[string]interface{})
							licenseInfo["type"] = "table"
							licenseInfo["raw"] = textContent

							licenses := make([]map[string]interface{}, 0)
							validFound := false

							// Parse data rows (skip header)
							for i := 1; i < len(lines); i++ {
								line := strings.TrimSpace(lines[i])
								if line == "" {
									continue
								}

								fields := regexp.MustCompile(`\s{2,}`).Split(line, -1)
								if len(fields) < 5 {
									continue
								}

								for j := range fields {
									fields[j] = strings.TrimSpace(fields[j])
								}

								entry := map[string]interface{}{
									"id":   fields[0],
									"uuid": fields[1],
								}

								if len(fields) > 2 {
									entry["uploaded_at"] = fields[2]
								}
								if len(fields) > 3 {
									entry["features"] = fields[3]
								}
								if len(fields) > 4 {
									expiresAt := fields[4]
									entry["expires_at"] = expiresAt

									if expTime, err := time.Parse(time.RFC3339, expiresAt); err == nil {
										if time.Now().Before(expTime) {
											entry["valid"] = true
											entry["expired"] = false
											validFound = true
										} else {
											entry["valid"] = false
											entry["expired"] = true
											*warnings = append(*warnings, fmt.Sprintf("License expired on %s", expiresAt))
										}
									} else {
										entry["valid"] = false
									}
								}
								if len(fields) > 5 {
									entry["trial"] = fields[5]
								}

								licenses = append(licenses, entry)
							}

							if len(licenses) > 0 {
								licenseInfo["licenses"] = licenses
							}

							if validFound {
								metadata.LicenseValid = true
							} else if !metadata.LicenseValid {
								metadata.LicenseValid = false
							}
							if !validFound && len(licenses) > 0 {
								*warnings = append(*warnings, "No valid licenses found in license-status.txt")
							}

							if jsonBytes, err := json.Marshal(licenseInfo); err == nil {
								metadata.LicenseStatus = json.RawMessage(jsonBytes)
							} else {
								metadata.LicenseStatus = json.RawMessage(fmt.Sprintf(`{"status": %q, "type": "table", "error": "failed to marshal"}`, textContent))
							}

						} else {
							// Check for common invalid license indicators
							lowerContent := strings.ToLower(textContent)
							if strings.Contains(lowerContent, "invalid") ||
								strings.Contains(lowerContent, "inactive") ||
								strings.Contains(lowerContent, "expired") ||
								strings.Contains(lowerContent, "error") ||
								strings.Contains(lowerContent, "no license") {
								metadata.LicenseValid = false
								*warnings = append(*warnings, fmt.Sprintf("License appears to be invalid: %s", textContent))
							} else {
								// Unknown format but no obvious error indicators
								metadata.LicenseValid = true
							}

							// Store as JSON with the text content
							metadata.LicenseStatus = json.RawMessage(fmt.Sprintf(`{"status": %q, "type": "plaintext"}`, textContent))
						}
					}
				}
			}
			_ = rc.Close()
		}
	}

	// Parse network/tailnet_debug.html for embedded build info snapshot
	if tailnetFile := findSibling(zr, "network/tailnet_debug.html"); tailnetFile != nil {
		if rc, err := tailnetFile.Open(); err == nil {
			if content, err := io.ReadAll(rc); err == nil {
				tracePattern := regexp.MustCompile(`<!-- trace ([A-Za-z0-9+/]+=*) -->`)
				if matches := tracePattern.FindSubmatch(content); len(matches) > 1 {
					decoded, err := base64.StdEncoding.DecodeString(string(matches[1]))
					if err != nil {
						*warnings = append(*warnings, fmt.Sprintf("Failed to decode base64 trace in tailnet_debug.html: %v", err))
					} else {
						decodedTrim := bytes.TrimSpace(decoded)
						if len(decodedTrim) > 0 {
							if json.Valid(decodedTrim) {
								metadata.TailnetBuildInfo = json.RawMessage(decodedTrim)
							} else {
								metadata.TailnetBuildInfo = json.RawMessage(fmt.Sprintf(`{"type":"plaintext","raw":%q}`, string(decodedTrim)))
							}
						}

						tailnetIsJSON := json.Valid(decodedTrim)
						if tailnetIsJSON {
							var tailnetInfo map[string]interface{}
							if err := json.Unmarshal(decodedTrim, &tailnetInfo); err == nil {
								if metadata.Version == "" {
									if v, ok := tailnetInfo["version"].(string); ok {
										metadata.Version = v
									}
								}
								if metadata.DashboardURL == "" {
									if d, ok := tailnetInfo["dashboard_url"].(string); ok {
										metadata.DashboardURL = d
									}
								}
								if metadata.DeploymentID == "" {
									if d, ok := tailnetInfo["deployment_id"].(string); ok {
										metadata.DeploymentID = d
									}
								}
							}
						}

						if len(buildInfoRaw) > 0 {
							buildInfoTrim := bytes.TrimSpace(buildInfoRaw)
							match := bytes.Equal(decodedTrim, buildInfoTrim)
							if !match && tailnetIsJSON && json.Valid(buildInfoTrim) {
								if jsonBytesEqual(decodedTrim, buildInfoTrim) {
									match = true
								}
							}
							if match {
								metadata.BuildInfoMatch = true
							} else {
								metadata.BuildInfoMismatch = "deployment/buildinfo.json differs from trace embedded in tailnet_debug.html"
								*warnings = append(*warnings, metadata.BuildInfoMismatch)
							}
						} else if tailnetIsJSON {
							metadata.BuildInfoMismatch = "Tailnet trace contains build info but deployment/buildinfo.json is missing"
							*warnings = append(*warnings, metadata.BuildInfoMismatch)
						} else if len(decodedTrim) > 0 {
							metadata.BuildInfoMismatch = "Tailnet trace is not valid JSON so build info comparison could not run"
							*warnings = append(*warnings, metadata.BuildInfoMismatch)
						}
					}
				}
			}
			_ = rc.Close()
		}
	}

	if healthFile := findSibling(zr, "deployment/health.json"); healthFile != nil {
		if rc, err := healthFile.Open(); err == nil {
			if content, err := io.ReadAll(rc); err == nil {
				status, err := parseHealthReport(content)
				if err != nil {
					*warnings = append(*warnings, fmt.Sprintf("deployment/health.json is not valid JSON: %v", err))
				} else if status != nil {
					metadata.HealthStatus = status
					if ts := status.Timestamp; ts != nil {
						utc := ts.UTC()
						status.Timestamp = &utc
						capturedAt = status.Timestamp
					}
					if !status.Healthy && status.Severity != "" {
						*warnings = append(*warnings, fmt.Sprintf("Health severity reported as %s", status.Severity))
					}
					if len(status.Warnings) > 0 {
						*warnings = append(*warnings, fmt.Sprintf("Health warnings detected (%d)", len(status.Warnings)))
					}
				}
			}
			_ = rc.Close()
		}
	}

	if capturedAt == nil {
		for _, f := range zr.File {
			if !strings.HasSuffix(f.Name, "cli_logs.txt") {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			content, err := io.ReadAll(rc)
			_ = rc.Close()
			if err != nil {
				continue
			}
			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if len(line) < len("2006-01-02 15:04:05.000") {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) < 2 {
					continue
				}
				ts := parts[0] + " " + parts[1]
				t, err := time.ParseInLocation("2006-01-02 15:04:05.000", ts, time.UTC)
				if err != nil {
					continue
				}
				capturedAt = &t
				break
			}
			if capturedAt != nil {
				break
			}
		}
	}

	parseNetworkInfo(zr, metadata, warnings)

	return capturedAt
}

func parseNetworkInfo(zr *zip.Reader, metadata *BundleMetadata, warnings *[]string) {
	if metadata == nil {
		return
	}

	type connectionRegionMeta struct {
		Code     string
		Name     string
		Embedded bool
		RegionID int
	}

	var (
		info           NetworkInfo
		dataFound      bool
		warnSet        = map[string]struct{}{}
		errSet         = map[string]struct{}{}
		connRegions    = map[int]connectionRegionMeta{}
		hostnameSuffix string
		haveConnInfo   bool
		forceWS        bool
		disableDirect  bool
		workspaceNotes []string
	)

	shouldPromote := func(kind, msg string) bool {
		trimmed := strings.TrimSpace(msg)
		if trimmed == "" {
			return false
		}
		lower := strings.ToLower(trimmed)
		if strings.Contains(lower, "probe stun:") {
			return false
		}
		if kind == "warning" && strings.HasPrefix(lower, "derp region") {
			return false
		}
		return true
	}

	addToSet := func(set map[string]struct{}, msg, kind string) {
		msg = strings.TrimSpace(msg)
		if msg == "" || set == nil {
			return
		}
		if !shouldPromote(kind, msg) {
			return
		}
		set[msg] = struct{}{}
	}

	addWarning := func(msg string) {
		addToSet(warnSet, msg, "warning")
	}

	addError := func(msg string) {
		addToSet(errSet, msg, "error")
	}

	boolPtr := func(v bool) *bool {
		val := v
		return &val
	}

	floatPtr := func(v float64) *float64 {
		val := v
		return &val
	}

	ensureUsage := func(info *NetworkInfo) *NetworkUsageSummary {
		if info.Usage == nil {
			info.Usage = &NetworkUsageSummary{}
		}
		return info.Usage
	}

	// connection_info.json
	if f := findSibling(zr, "network/connection_info.json"); f != nil {
		dataFound = true
		content, err := readZipFile(f)
		if err != nil {
			msg := fmt.Sprintf("failed to read network/connection_info.json: %v", err)
			addError(msg)
		} else {
			var payload struct {
				DerpMap struct {
					Regions map[string]struct {
						EmbeddedRelay bool   `json:"EmbeddedRelay"`
						RegionID      int    `json:"RegionID"`
						RegionCode    string `json:"RegionCode"`
						RegionName    string `json:"RegionName"`
					} `json:"Regions"`
				} `json:"derp_map"`
				DerpForceWebsockets      bool   `json:"derp_force_websockets"`
				DisableDirectConnections bool   `json:"disable_direct_connections"`
				HostnameSuffix           string `json:"hostname_suffix"`
			}
			if err := json.Unmarshal(content, &payload); err != nil {
				msg := fmt.Sprintf("failed to parse network/connection_info.json: %v", err)
				addError(msg)
			} else {
				haveConnInfo = true
				forceWS = payload.DerpForceWebsockets
				disableDirect = payload.DisableDirectConnections
				hostnameSuffix = strings.TrimSpace(payload.HostnameSuffix)

				usage := ensureUsage(&info)
				usage.ForceWebsockets = boolPtr(forceWS)
				usage.DirectConnectionsDisabled = boolPtr(disableDirect)
				usage.WorkspaceProxy = boolPtr(disableDirect)
				if disableDirect {
					workspaceNotes = append(workspaceNotes, "Direct connections are disabled (disable_direct_connections=true)")
				}

				for _, region := range payload.DerpMap.Regions {
					connRegions[region.RegionID] = connectionRegionMeta{
						Code:     strings.TrimSpace(region.RegionCode),
						Name:     strings.TrimSpace(region.RegionName),
						Embedded: region.EmbeddedRelay,
						RegionID: region.RegionID,
					}
				}
			}
		}
	}

	var (
		stunSeen        bool
		stunSuccessful  bool
		embeddedInUse   bool
		preferredDERP   string
		preferredRegion string
	)

	// netcheck.json
	if f := findSibling(zr, "network/netcheck.json"); f != nil {
		dataFound = true
		content, err := readZipFile(f)
		if err != nil {
			msg := fmt.Sprintf("failed to read network/netcheck.json: %v", err)
			addError(msg)
		} else {
			var payload struct {
				Severity string `json:"severity"`
				Warnings []any  `json:"warnings"`
				Healthy  bool   `json:"healthy"`
				Regions  map[string]struct {
					Healthy  bool   `json:"healthy"`
					Severity string `json:"severity"`
					Warnings []any  `json:"warnings"`
					Region   struct {
						EmbeddedRelay bool   `json:"EmbeddedRelay"`
						RegionID      int    `json:"RegionID"`
						RegionCode    string `json:"RegionCode"`
						RegionName    string `json:"RegionName"`
					} `json:"region"`
					NodeReports []struct {
						Healthy             bool       `json:"healthy"`
						Severity            string     `json:"severity"`
						Warnings            []any      `json:"warnings"`
						UsesWebsocket       bool       `json:"uses_websocket"`
						CanExchangeMessages bool       `json:"can_exchange_messages"`
						ClientErrs          []any      `json:"client_errs"`
						ClientLogs          [][]string `json:"client_logs"`
						Stun                struct {
							Enabled *bool `json:"Enabled"`
							CanSTUN *bool `json:"CanSTUN"`
							Error   any   `json:"Error"`
						} `json:"stun"`
					} `json:"node_reports"`
				} `json:"regions"`
				Netcheck struct {
					UDP                   *bool                  `json:"UDP"`
					IPv4                  *bool                  `json:"IPv4"`
					IPv6                  *bool                  `json:"IPv6"`
					IPv4CanSend           *bool                  `json:"IPv4CanSend"`
					IPv6CanSend           *bool                  `json:"IPv6CanSend"`
					OSHasIPv6             *bool                  `json:"OSHasIPv6"`
					ICMPv4                *bool                  `json:"ICMPv4"`
					MappingVariesByDestIP *bool                  `json:"MappingVariesByDestIP"`
					HairPinning           *bool                  `json:"HairPinning"`
					UPnP                  *bool                  `json:"UPnP"`
					PMP                   *bool                  `json:"PMP"`
					PCP                   *bool                  `json:"PCP"`
					CaptivePortal         any                    `json:"CaptivePortal"`
					PreferredDERP         *int                   `json:"PreferredDERP"`
					RegionLatency         map[string]json.Number `json:"RegionLatency"`
					RegionV4Latency       map[string]json.Number `json:"RegionV4Latency"`
					RegionV6Latency       map[string]json.Number `json:"RegionV6Latency"`
					GlobalV4              string                 `json:"GlobalV4"`
					GlobalV6              string                 `json:"GlobalV6"`
				} `json:"netcheck"`
				NetcheckLogs []string `json:"netcheck_logs"`
			}
			if err := json.Unmarshal(content, &payload); err != nil {
				msg := fmt.Sprintf("failed to parse network/netcheck.json: %v", err)
				addError(msg)
			} else {
				info.Health = &NetworkHealthSummary{
					Healthy:  payload.Healthy,
					Severity: strings.ToLower(strings.TrimSpace(payload.Severity)),
				}
				if payload.Healthy {
					info.Health.Message = "Netcheck reports healthy connectivity"
				} else if payload.Severity != "" {
					info.Health.Message = fmt.Sprintf("Netcheck severity: %s", payload.Severity)
				} else {
					info.Health.Message = "Netcheck reported connectivity issues"
				}

				for _, warn := range flattenMessages(payload.Warnings) {
					addWarning(warn)
				}

				if len(payload.NetcheckLogs) > 0 {
					if len(payload.NetcheckLogs) > 50 {
						info.NetcheckLogs = append([]string(nil), payload.NetcheckLogs[:50]...)
					} else {
						info.NetcheckLogs = append([]string(nil), payload.NetcheckLogs...)
					}
				}

				usage := ensureUsage(&info)
				if payload.Netcheck.UDP != nil {
					usage.UDP = boolPtr(*payload.Netcheck.UDP)
				}
				if payload.Netcheck.IPv4 != nil {
					usage.IPv4 = boolPtr(*payload.Netcheck.IPv4)
				}
				if payload.Netcheck.IPv6 != nil {
					usage.IPv6 = boolPtr(*payload.Netcheck.IPv6)
				}
				if payload.Netcheck.IPv4CanSend != nil {
					usage.IPv4CanSend = boolPtr(*payload.Netcheck.IPv4CanSend)
				}
				if payload.Netcheck.IPv6CanSend != nil {
					usage.IPv6CanSend = boolPtr(*payload.Netcheck.IPv6CanSend)
				}
				if payload.Netcheck.OSHasIPv6 != nil {
					usage.OSHasIPv6 = boolPtr(*payload.Netcheck.OSHasIPv6)
				}
				if payload.Netcheck.ICMPv4 != nil {
					usage.ICMPv4 = boolPtr(*payload.Netcheck.ICMPv4)
				}
				if payload.Netcheck.MappingVariesByDestIP != nil {
					usage.MappingVariesByDestIP = boolPtr(*payload.Netcheck.MappingVariesByDestIP)
				}
				if payload.Netcheck.HairPinning != nil {
					usage.HairPinning = boolPtr(*payload.Netcheck.HairPinning)
				}
				if payload.Netcheck.UPnP != nil {
					usage.UPnP = boolPtr(*payload.Netcheck.UPnP)
				}
				if payload.Netcheck.PMP != nil {
					usage.PMP = boolPtr(*payload.Netcheck.PMP)
				}
				if payload.Netcheck.PCP != nil {
					usage.PCP = boolPtr(*payload.Netcheck.PCP)
				}
				if payload.Netcheck.CaptivePortal != nil {
					var cp string
					switch v := payload.Netcheck.CaptivePortal.(type) {
					case string:
						cp = strings.TrimSpace(v)
					case fmt.Stringer:
						cp = strings.TrimSpace(v.String())
					default:
						cp = strings.TrimSpace(fmt.Sprint(v))
					}
					if cp == "" || strings.EqualFold(cp, "null") {
						cp = "None detected"
					}
					usage.CaptivePortal = &cp
				}
				if payload.Netcheck.GlobalV4 != "" {
					usage.GlobalV4 = payload.Netcheck.GlobalV4
				}
				if payload.Netcheck.GlobalV6 != "" {
					usage.GlobalV6 = payload.Netcheck.GlobalV6
				}

				if payload.Netcheck.PreferredDERP != nil {
					id := *payload.Netcheck.PreferredDERP
					if id != 0 {
						if meta, ok := connRegions[id]; ok {
							preferredRegion = meta.Name
							if preferredRegion == "" && meta.Code != "" {
								preferredRegion = meta.Code
							}
							preferredDERP = fmt.Sprintf("%d", id)
							if preferredRegion != "" {
								preferredDERP = fmt.Sprintf("%d (%s)", id, preferredRegion)
							}
							if meta.Embedded {
								embeddedInUse = true
							}
						} else {
							preferredDERP = fmt.Sprintf("%d", id)
							if reg, ok := payload.Regions[strconv.Itoa(id)]; ok {
								if name := strings.TrimSpace(reg.Region.RegionName); name != "" {
									if preferredRegion == "" {
										preferredRegion = name
									}
									preferredDERP = fmt.Sprintf("%d (%s)", id, name)
								}
								if reg.Region.EmbeddedRelay {
									embeddedInUse = true
								}
							}
						}
					}
				}

				latencyForRegion := func(key string) *float64 {
					if payload.Netcheck.RegionLatency != nil {
						if v, ok := payload.Netcheck.RegionLatency[key]; ok {
							if ns, err := v.Int64(); err == nil {
								ms := float64(ns) / 1e6
								return floatPtr(ms)
							}
						}
					}
					if payload.Netcheck.RegionV4Latency != nil {
						if v, ok := payload.Netcheck.RegionV4Latency[key]; ok {
							if ns, err := v.Int64(); err == nil {
								ms := float64(ns) / 1e6
								return floatPtr(ms)
							}
						}
					}
					if payload.Netcheck.RegionV6Latency != nil {
						if v, ok := payload.Netcheck.RegionV6Latency[key]; ok {
							if ns, err := v.Int64(); err == nil {
								ms := float64(ns) / 1e6
								return floatPtr(ms)
							}
						}
					}
					return nil
				}

				for regionKey, region := range payload.Regions {
					status := NetworkRegionStatus{
						Healthy:  region.Healthy,
						Severity: strings.ToLower(strings.TrimSpace(region.Severity)),
					}
					if region.Region.RegionID != 0 {
						status.RegionID = region.Region.RegionID
					} else if id, err := strconv.Atoi(regionKey); err == nil {
						status.RegionID = id
					}
					status.Code = strings.TrimSpace(region.Region.RegionCode)
					status.Name = strings.TrimSpace(region.Region.RegionName)
					status.EmbeddedRelay = region.Region.EmbeddedRelay
					if status.Name == "" && status.Code != "" {
						status.Name = status.Code
					}

					if status.RegionID != 0 {
						if meta, ok := connRegions[status.RegionID]; ok {
							status.EmbeddedRelay = status.EmbeddedRelay || meta.Embedded
							if status.Name == "" {
								status.Name = meta.Name
							}
							if status.Code == "" {
								status.Code = meta.Code
							}
						}
					}

					for _, warn := range flattenMessages(region.Warnings) {
						addWarning(warn)
					}

					if lat := latencyForRegion(regionKey); lat != nil {
						status.LatencyMS = lat
					}

					var (
						seenWebsocket bool
						websocketVal  bool
						seenExchange  bool
						exchangeVal   bool
					)

					for _, node := range region.NodeReports {
						for _, warn := range flattenMessages(node.Warnings) {
							addWarning(warn)
							status.Warnings = append(status.Warnings, warn)
						}

						if node.UsesWebsocket {
							websocketVal = true
							seenWebsocket = true
						} else if !seenWebsocket {
							seenWebsocket = true
							websocketVal = false
						}

						if node.CanExchangeMessages {
							exchangeVal = true
							seenExchange = true
						} else if !seenExchange {
							seenExchange = true
							exchangeVal = false
						}

						if node.Stun.Enabled != nil {
							stunSeen = true
							if node.Stun.CanSTUN != nil {
								if *node.Stun.CanSTUN {
									stunSuccessful = true
								}
							}
						}
						if node.Stun.CanSTUN != nil {
							stunSeen = true
							if *node.Stun.CanSTUN {
								stunSuccessful = true
							}
						}
						if node.Stun.Error != nil {
							text := strings.TrimSpace(fmt.Sprint(node.Stun.Error))
							if text != "" && text != "[]" {
								status.Errors = append(status.Errors, text)
								addError(text)
							}
						}

						for _, errVal := range node.ClientErrs {
							text := strings.TrimSpace(fmt.Sprint(errVal))
							if text == "" || text == "[]" {
								continue
							}
							status.Errors = append(status.Errors, text)
							addError(text)
						}
					}

					if seenWebsocket {
						status.UsesWebsocket = boolPtr(websocketVal)
					}
					if seenExchange {
						status.CanExchangeMessages = boolPtr(exchangeVal)
					}

					if !status.Healthy {
						desc := status.Name
						if desc == "" && status.Code != "" {
							desc = status.Code
						}
						if desc == "" && status.RegionID != 0 {
							desc = fmt.Sprintf("DERP region %d", status.RegionID)
						}
						if desc != "" {
							addWarning(fmt.Sprintf("DERP region %s reported issues", desc))
						}
					}

					if len(status.Warnings) > 0 {
						sort.Strings(status.Warnings)
					} else {
						status.Warnings = nil
					}
					if len(status.Errors) > 0 {
						sort.Strings(status.Errors)
					} else {
						status.Errors = nil
					}

					info.Regions = append(info.Regions, status)
				}
			}
		}
	}

	// interfaces.json
	if f := findSibling(zr, "network/interfaces.json"); f != nil {
		dataFound = true
		content, err := readZipFile(f)
		if err != nil {
			msg := fmt.Sprintf("failed to read network/interfaces.json: %v", err)
			addError(msg)
		} else {
			var payload struct {
				Severity   string   `json:"severity"`
				Warnings   []string `json:"warnings"`
				Interfaces []struct {
					Name      string   `json:"name"`
					MTU       int      `json:"mtu"`
					Addresses []string `json:"addresses"`
				} `json:"interfaces"`
			}
			if err := json.Unmarshal(content, &payload); err != nil {
				msg := fmt.Sprintf("failed to parse network/interfaces.json: %v", err)
				addError(msg)
			} else {
				sev := strings.ToLower(strings.TrimSpace(payload.Severity))
				if sev != "" && sev != "ok" {
					addWarning(fmt.Sprintf("Interface report severity: %s", payload.Severity))
				}
				for _, warn := range payload.Warnings {
					addWarning(warn)
				}
				for _, iface := range payload.Interfaces {
					info.Interfaces = append(info.Interfaces, NetworkInterfaceInfo{
						Name:      iface.Name,
						MTU:       iface.MTU,
						Addresses: append([]string(nil), iface.Addresses...),
					})
				}
			}
		}
	}

	if haveConnInfo && info.Usage != nil {
		if embeddedInUse {
			info.Usage.UsesEmbeddedDERP = boolPtr(true)
		} else if len(connRegions) > 0 {
			info.Usage.UsesEmbeddedDERP = boolPtr(false)
		}
	}
	if preferredDERP != "" {
		if info.Usage == nil {
			info.Usage = &NetworkUsageSummary{}
		}
		info.Usage.PreferredDERP = preferredDERP
		if embeddedInUse && preferredRegion != "" {
			info.Usage.EmbeddedDERPRegion = preferredRegion
		} else if embeddedInUse {
			info.Usage.EmbeddedDERPRegion = preferredDERP
		}
	}
	if info.Usage != nil && len(workspaceNotes) > 0 {
		info.Usage.WorkspaceProxyReason = strings.Join(workspaceNotes, "; ")
	}

	if stunSeen {
		if info.Usage == nil {
			info.Usage = &NetworkUsageSummary{}
		}
		info.Usage.UsesSTUN = boolPtr(stunSuccessful)
		if !stunSuccessful {
			addWarning("STUN probes did not succeed")
		}
	}

	if hostnameSuffix != "" {
		info.HostnameSuffix = hostnameSuffix
	}

	if len(info.Regions) > 0 {
		sort.Slice(info.Regions, func(i, j int) bool {
			if info.Regions[i].Healthy != info.Regions[j].Healthy {
				return !info.Regions[i].Healthy && info.Regions[j].Healthy
			}
			if info.Regions[i].Severity != info.Regions[j].Severity {
				return info.Regions[i].Severity < info.Regions[j].Severity
			}
			return info.Regions[i].Name < info.Regions[j].Name
		})
	}

	if len(info.Interfaces) > 0 {
		sort.Slice(info.Interfaces, func(i, j int) bool {
			return info.Interfaces[i].Name < info.Interfaces[j].Name
		})
	}

	if len(info.NetcheckLogs) > 0 {
		// Keep deterministic order, already in order but clone.
		info.NetcheckLogs = append([]string(nil), info.NetcheckLogs...)
	}

	if len(warnSet) > 0 {
		info.Warnings = make([]string, 0, len(warnSet))
		for msg := range warnSet {
			info.Warnings = append(info.Warnings, msg)
		}
		sort.Strings(info.Warnings)
	}
	if len(errSet) > 0 {
		info.Errors = make([]string, 0, len(errSet))
		for msg := range errSet {
			info.Errors = append(info.Errors, msg)
		}
		sort.Strings(info.Errors)
	}

	if dataFound || len(info.Warnings) > 0 || len(info.Errors) > 0 {
		metadata.Network = &info
	}
}

func parseHealthReport(content []byte) (*HealthStatus, error) {
	var base struct {
		Time     string `json:"time"`
		Healthy  bool   `json:"healthy"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(content, &base); err != nil {
		return nil, err
	}

	var raw any
	if err := json.Unmarshal(content, &raw); err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	collectWarnings(raw, seen)

	warnings := make([]string, 0, len(seen))
	for w := range seen {
		warnings = append(warnings, w)
	}
	sort.Strings(warnings)
	if len(warnings) == 0 {
		warnings = nil
	}

	status := &HealthStatus{
		Healthy:  base.Healthy,
		Severity: strings.ToLower(base.Severity),
		Warnings: warnings,
	}

	if base.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, base.Time); err == nil {
			status.Timestamp = &t
		}
	}

	if rawMap, ok := raw.(map[string]any); ok {
		keys := make([]string, 0, len(rawMap))
		for key := range rawMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		components := make([]HealthComponent, 0)
		notes := make([]string, 0)

		getBool := func(v any) bool {
			switch b := v.(type) {
			case bool:
				return b
			case string:
				l := strings.ToLower(strings.TrimSpace(b))
				return l == "true" || l == "1"
			case float64:
				return b != 0
			}
			return false
		}

		buildComponent := func(key string, value any) (*HealthComponent, string) {
			m, ok := value.(map[string]any)
			if !ok {
				return nil, ""
			}

			comp := &HealthComponent{
				Name:     humanizeKey(key),
				Healthy:  true,
				Severity: "",
			}
			if h, ok := m["healthy"]; ok {
				comp.Healthy = getBool(h)
			}
			if sev, ok := m["severity"]; ok {
				comp.Severity = strings.ToLower(strings.TrimSpace(fmt.Sprint(sev)))
			}
			if comp.Severity == "" && !comp.Healthy {
				comp.Severity = "error"
			}
			if dismissed, ok := m["dismissed"].(bool); ok {
				comp.Dismissed = dismissed
			}

			messages := make([]string, 0)
			if warns, ok := m["warnings"]; ok {
				messages = append(messages, flattenMessages(warns)...)
			}
			if errs, ok := m["errors"]; ok {
				messages = append(messages, flattenMessages(errs)...)
			}
			if statusMap, ok := m["status"].(map[string]any); ok {
				if s := strings.TrimSpace(fmt.Sprint(statusMap["status"])); s != "" && strings.ToLower(s) != "ok" {
					messages = append(messages, fmt.Sprintf("Status: %s", humanizeKey(s)))
				}
				if rep, ok := statusMap["report"].(map[string]any); ok {
					messages = append(messages, flattenMessages(rep["errors"])...)
					messages = append(messages, flattenMessages(rep["warnings"])...)
				}
			}

			if key == "workspace_proxy" {
				if proxies, ok := m["workspace_proxies"].(map[string]any); ok {
					if regions, ok := proxies["regions"].([]any); ok {
						for _, region := range regions {
							rm, ok := region.(map[string]any)
							if !ok {
								continue
							}
							if getBool(rm["healthy"]) {
								continue
							}
							name := strings.TrimSpace(fmt.Sprint(rm["display_name"]))
							if name == "" {
								name = strings.TrimSpace(fmt.Sprint(rm["name"]))
							}
							statusMsg := ""
							if statusMap, ok := rm["status"].(map[string]any); ok {
								if s := strings.TrimSpace(fmt.Sprint(statusMap["status"])); s != "" && strings.ToLower(s) != "ok" {
									statusMsg = humanizeKey(s)
								}
								if rep, ok := statusMap["report"].(map[string]any); ok {
									if errs := flattenMessages(rep["errors"]); len(errs) > 0 {
										messages = append(messages, fmt.Sprintf("%s proxy error: %s", name, errs[0]))
										if len(errs) > 1 {
											messages = append(messages, errs[1:]...)
										}
										statusMsg = ""
									} else if warns := flattenMessages(rep["warnings"]); len(warns) > 0 {
										messages = append(messages, fmt.Sprintf("%s proxy warning: %s", name, warns[0]))
										if len(warns) > 1 {
											messages = append(messages, warns[1:]...)
										}
										statusMsg = ""
									}
								}
							}
							if statusMsg != "" {
								messages = append(messages, fmt.Sprintf("%s proxy status: %s", name, statusMsg))
							}
						}
					}
				}
			}

			messages = dedupeStrings(messages)
			hasIssue := !comp.Healthy || (comp.Severity != "" && comp.Severity != "ok") || len(messages) > 0
			if comp.Dismissed && len(messages) == 0 {
				messages = append(messages, "Issue dismissed")
			}
			if comp.Dismissed {
				hasIssue = true
			}
			if key == "derp" {
				if hasIssue {
					return nil, "DERP health issues are summarised in Network Information."
				}
				return nil, ""
			}
			if !hasIssue {
				return nil, ""
			}
			if comp.Healthy {
				comp.Healthy = false
			}
			if comp.Severity == "" || strings.ToLower(comp.Severity) == "ok" {
				comp.Severity = "warning"
			}
			comp.Messages = messages
			return comp, ""
		}
		for _, key := range keys {
			if key == "time" || key == "healthy" || key == "severity" {
				continue
			}
			component, note := buildComponent(key, rawMap[key])
			if note != "" {
				notes = append(notes, note)
			}
			if component != nil {
				components = append(components, *component)
			}
		}
		if len(components) > 0 {
			status.Components = components
		}
		if len(notes) > 0 {
			status.Notes = dedupeStrings(notes)
		}
	}

	return status, nil
}

func collectWarnings(value any, seen map[string]struct{}) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if key == "warnings" {
				switch arr := child.(type) {
				case []any:
					for _, item := range arr {
						if s, ok := item.(string); ok {
							s = strings.TrimSpace(s)
							if s != "" {
								seen[s] = struct{}{}
							}
						}
					}
				}
			}
			collectWarnings(child, seen)
		}
	case []any:
		for _, item := range v {
			collectWarnings(item, seen)
		}
	}
}

func jsonBytesEqual(a, b []byte) bool {
	var objA any
	if err := json.Unmarshal(a, &objA); err != nil {
		return false
	}

	var objB any
	if err := json.Unmarshal(b, &objB); err != nil {
		return false
	}

	return reflect.DeepEqual(objA, objB)
}

func readZipFile(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

func findSibling(zr *zip.Reader, name string) *zip.File {
	for _, f := range zr.File {
		if f.Name == name {
			return f
		}
	}
	return nil
}

func flattenMessages(value any) []string {
	var out []string
	var visit func(any)
	visit = func(value any) {
		switch v := value.(type) {
		case nil:
			return
		case string:
			s := strings.TrimSpace(v)
			if s != "" {
				out = append(out, s)
			}
		case []any:
			for _, child := range v {
				visit(child)
			}
		case []string:
			for _, child := range v {
				visit(child)
			}
		case map[string]any:
			message := ""
			if msg, ok := v["message"]; ok {
				message = strings.TrimSpace(fmt.Sprint(msg))
			}
			if message == "" {
				for _, key := range []string{"detail", "description", "summary", "error", "reason"} {
					if msg, ok := v[key]; ok {
						message = strings.TrimSpace(fmt.Sprint(msg))
						if message != "" {
							break
						}
					}
				}
			}
			code := strings.TrimSpace(fmt.Sprint(v["code"]))
			if message == "" && code != "" {
				message = code
			} else if message != "" && code != "" {
				message = fmt.Sprintf("%s: %s", code, message)
			}
			if message != "" {
				out = append(out, message)
			} else {
				pretty := strings.TrimSpace(fmt.Sprint(v))
				if pretty != "" && pretty != "map[]" {
					out = append(out, pretty)
				}
			}
		default:
			s := strings.TrimSpace(fmt.Sprint(v))
			if s != "" && s != "[]" {
				out = append(out, s)
			}
		}
	}
	visit(value)
	return out
}

func humanizeKey(key string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "Unknown"
	}
	replacer := strings.NewReplacer("_", " ", "-", " ")
	key = replacer.Replace(key)
	parts := strings.Fields(key)
	for i, part := range parts {
		lower := strings.ToLower(part)
		if len(lower) == 0 {
			continue
		}
		parts[i] = strings.ToUpper(lower[:1]) + lower[1:]
	}
	return strings.Join(parts, " ")
}

func dedupeStrings(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
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

func profileGroupFromPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, "/agent/"):
		return "agent"
	case strings.Contains(lower, "/coder/"):
		return "server"
	case strings.Contains(lower, "/deployment/"):
		return "server"
	default:
		return "server"
	}
}

// Aggregations (Top + Flame)
type TopRow struct {
	Func        string  `json:"func"`
	File        string  `json:"file"`
	Flat        int64   `json:"flat"`
	Cum         int64   `json:"cum"`
	FlatPercent float64 `json:"flatPct"`
	CumPercent  float64 `json:"cumPct"`
}

func buildTop(p *profile.Profile, valueIndex int, filter string) ([]TopRow, error) {
	if valueIndex < 0 || valueIndex >= len(p.SampleType) {
		valueIndex = 0
	}

	var filterRe *regexp.Regexp
	if filter != "" {
		var err error
		filterRe, err = regexp.Compile("(?i)" + regexp.QuoteMeta(filter))
		if err != nil {
			return nil, fmt.Errorf("invalid filter: %w", err)
		}
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
					if filterRe == nil || filterRe.MatchString(line.Function.Name) {
						cum[line.Function.ID] += v
					}
				}
			}
		}

		if len(s.Location) > 0 {
			leaf := s.Location[0]
			if len(leaf.Line) > 0 && leaf.Line[0].Function != nil {
				if filterRe == nil || filterRe.MatchString(leaf.Line[0].Function.Name) {
					flat[leaf.Line[0].Function.ID] += v
				}
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

// Optimized FlameNode with map-based child lookup
type FlameNode struct {
	Name     string                `json:"name"`
	Value    int64                 `json:"value"`
	Children []*FlameNode          `json:"children,omitempty"`
	childMap map[string]*FlameNode `json:"-"` // Fast lookup
}

func (n *FlameNode) getChild(name string) *FlameNode {
	if n.childMap == nil {
		n.childMap = make(map[string]*FlameNode)
		for _, c := range n.Children {
			n.childMap[c.Name] = c
		}
	}

	if child, exists := n.childMap[name]; exists {
		return child
	}

	child := &FlameNode{Name: name}
	n.Children = append(n.Children, child)
	n.childMap[name] = child
	return child
}

func buildFlame(p *profile.Profile, valueIndex int) (*FlameNode, error) {
	if valueIndex < 0 || valueIndex >= len(p.SampleType) {
		valueIndex = 0
	}

	root := &FlameNode{Name: "root"}

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
			cur = cur.getChild(fn)
			cur.Value += v
		}
	}

	var sortRec func(n *FlameNode)
	sortRec = func(n *FlameNode) {
		for _, c := range n.Children {
			sortRec(c)
		}
		sort.Slice(n.Children, func(i, j int) bool {
			return n.Children[i].Value > n.Children[j].Value
		})
	}
	sortRec(root)

	return root, nil
}

// Profile comparison and diff
type ComparisonResult struct {
	Profile1 string              `json:"profile1"`
	Profile2 string              `json:"profile2"`
	Diff     []ComparisonDiffRow `json:"diff"`
}

type ComparisonDiffRow struct {
	Func     string  `json:"func"`
	Flat1    int64   `json:"flat1"`
	Flat2    int64   `json:"flat2"`
	FlatDiff int64   `json:"flatDiff"`
	PctDiff  float64 `json:"pctDiff"`
}

// Flame graph diff support
type FlameDiffNode struct {
	Name     string                    `json:"name"`
	Value1   int64                     `json:"value1"`
	Value2   int64                     `json:"value2"`
	Diff     int64                     `json:"diff"`
	PctDiff  float64                   `json:"pctDiff"`
	Children []*FlameDiffNode          `json:"children,omitempty"`
	childMap map[string]*FlameDiffNode `json:"-"`
}

func (n *FlameDiffNode) getChild(name string) *FlameDiffNode {
	if n.childMap == nil {
		n.childMap = make(map[string]*FlameDiffNode)
		for _, c := range n.Children {
			n.childMap[c.Name] = c
		}
	}

	if child, exists := n.childMap[name]; exists {
		return child
	}

	child := &FlameDiffNode{Name: name}
	n.Children = append(n.Children, child)
	n.childMap[name] = child
	return child
}

func buildFlameDiff(p1, p2 *profile.Profile, valueIndex int) (*FlameDiffNode, error) {
	if valueIndex < 0 || valueIndex >= len(p1.SampleType) {
		valueIndex = 0
	}

	root := &FlameDiffNode{Name: "root"}

	// Build flame graph for profile 1
	for _, s := range p1.Sample {
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
			cur = cur.getChild(fn)
			cur.Value1 += v
		}
	}

	// Build flame graph for profile 2
	for _, s := range p2.Sample {
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
			cur = cur.getChild(fn)
			cur.Value2 += v
		}
	}

	// Calculate diffs
	var calcDiffs func(n *FlameDiffNode)
	calcDiffs = func(n *FlameDiffNode) {
		n.Diff = n.Value2 - n.Value1
		if n.Value1 > 0 {
			n.PctDiff = float64(n.Diff) * 100 / float64(n.Value1)
		}
		for _, c := range n.Children {
			calcDiffs(c)
		}
	}
	calcDiffs(root)

	// Sort by absolute diff
	var sortRec func(n *FlameDiffNode)
	sortRec = func(n *FlameDiffNode) {
		for _, c := range n.Children {
			sortRec(c)
		}
		sort.Slice(n.Children, func(i, j int) bool {
			absI := n.Children[i].Diff
			if absI < 0 {
				absI = -absI
			}
			absJ := n.Children[j].Diff
			if absJ < 0 {
				absJ = -absJ
			}
			return absI > absJ
		})
	}
	sortRec(root)

	return root, nil
}

func compareProfiles(p1, p2 *StoredProfile, valueIndex int) (*ComparisonResult, error) {
	top1, err := buildTop(p1.Profile, valueIndex, "")
	if err != nil {
		return nil, fmt.Errorf("build top for %s: %w", p1.Name, err)
	}

	top2, err := buildTop(p2.Profile, valueIndex, "")
	if err != nil {
		return nil, fmt.Errorf("build top for %s: %w", p2.Name, err)
	}

	// Build maps for comparison
	flat1 := make(map[string]int64)
	flat2 := make(map[string]int64)

	for _, row := range top1 {
		flat1[row.Func] = row.Flat
	}
	for _, row := range top2 {
		flat2[row.Func] = row.Flat
	}

	// Find all functions
	allFuncs := make(map[string]bool)
	for f := range flat1 {
		allFuncs[f] = true
	}
	for f := range flat2 {
		allFuncs[f] = true
	}

	// Build comparison
	result := &ComparisonResult{
		Profile1: p1.Name,
		Profile2: p2.Name,
		Diff:     []ComparisonDiffRow{},
	}

	for f := range allFuncs {
		v1 := flat1[f]
		v2 := flat2[f]
		diff := v2 - v1

		var pctDiff float64
		if v1 > 0 {
			pctDiff = float64(diff) * 100 / float64(v1)
		}

		result.Diff = append(result.Diff, ComparisonDiffRow{
			Func:     f,
			Flat1:    v1,
			Flat2:    v2,
			FlatDiff: diff,
			PctDiff:  pctDiff,
		})
	}

	// Sort by absolute difference
	sort.Slice(result.Diff, func(i, j int) bool {
		absI := result.Diff[i].FlatDiff
		if absI < 0 {
			absI = -absI
		}
		absJ := result.Diff[j].FlatDiff
		if absJ < 0 {
			absJ = -absJ
		}
		return absI > absJ
	})

	return result, nil
}

// Native pprof UI (per-profile) via reverse proxy
func (s *Store) ensurePprofTarget(ctx context.Context, id string) (*url.URL, error) {
	// Check if already running
	s.pprofMu.RLock()
	if inst := s.pprofTargets[id]; inst != nil {
		s.pprofMu.RUnlock()
		return inst.URL, nil
	}
	s.pprofMu.RUnlock()

	// Rate limit concurrent operations
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-time.After(5 * time.Second):
		return nil, errors.New("too many concurrent pprof instances")
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	p, ok := s.GetProfile(id)
	if !ok {
		return nil, errors.New("profile not found")
	}

	// Decompress profile
	dec, _, err := detectAndDecompressAll(p.Bytes)
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}

	// Write to temp file
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

	// Find free port
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = os.Remove(tf.Name())
		return nil, fmt.Errorf("port pick: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	targetStr := fmt.Sprintf("http://127.0.0.1:%d", port)
	targetURL, _ := url.Parse(targetStr)

	// Launch pprof with context
	pprofCtx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(pprofCtx, "go", "tool", "pprof",
		"-no_browser",
		"-http="+fmt.Sprintf("127.0.0.1:%d", port),
		tf.Name(),
	)

	// Prevent browser launch
	cmd.Env = append(os.Environ(),
		"PPROF_NO_BROWSER=1",
		"BROWSER=none",
	)

	if err := cmd.Start(); err != nil {
		cancel()
		_ = os.Remove(tf.Name())
		return nil, fmt.Errorf("start pprof: %w", err)
	}

	// Wait for server to be ready
	deadline := time.Now().Add(8 * time.Second)
	for {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		if time.Now().After(deadline) {
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			cancel()
			_ = os.Remove(tf.Name())
			return nil, fmt.Errorf("pprof did not come up on %s in time", targetStr)
		}
		select {
		case <-ctx.Done():
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
			}
			cancel()
			_ = os.Remove(tf.Name())
			return nil, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}

	// Cache instance
	inst := &pprofInstance{
		URL:       targetURL,
		Process:   cmd,
		Cancel:    cancel,
		TempFile:  tf.Name(),
		CreatedAt: time.Now(),
	}

	s.pprofMu.Lock()
	s.pprofTargets[id] = inst
	s.pprofMu.Unlock()

	activeProfiles.Inc()
	s.logger.Info("started pprof instance",
		slog.String("id", id),
		slog.String("url", targetStr))

	// Cleanup on exit
	go func() {
		_ = cmd.Wait()
		_ = os.Remove(tf.Name())
		s.pprofMu.Lock()
		delete(s.pprofTargets, id)
		s.pprofMu.Unlock()
		activeProfiles.Dec()
		cancel()
		s.logger.Info("pprof instance exited", slog.String("id", id))
	}()

	// Auto-cleanup after timeout
	go func() {
		select {
		case <-time.After(pprofTimeout):
			s.logger.Info("pprof instance timeout", slog.String("id", id))
			cancel()
		case <-pprofCtx.Done():
		}
	}()

	return targetURL, nil
}

// HTTP Handlers
func withMetrics(name string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		h(w, r)
		requestDuration.WithLabelValues(name, r.Method).Observe(time.Since(start).Seconds())
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

func serveCSS(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	_, _ = w.Write(styleCSS)
}

func handleListBundles(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bundles := s.GetAllBundles()
		writeJSON(w, bundles)
	}
}

func handlePrometheusStatus(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		bundle, ok := s.GetBundle(id)
		if !ok {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		s.promMu.Lock()
		inst := s.promInstances[id]
		s.promMu.Unlock()
		writeJSON(w, map[string]any{
			"snapshots": bundle.Prometheus,
			"instance":  inst,
		})
	}
}

func handlePrometheusStart(s *Store) http.HandlerFunc {
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

func handlePrometheusStop(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		s.StopPrometheus(id)
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleGetBundle(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		b, ok := s.GetBundle(id)
		if !ok {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		writeJSON(w, b)
	}
}

func handleProfileSummary(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		p, ok := s.GetProfile(id)
		if !ok {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		writeJSON(w, p)
	}
}

func handleProfileTop(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		p, ok := s.GetProfile(id)
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

		filter := r.URL.Query().Get("filter")

		rows, err := buildTop(p.Profile, vi, filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, rows)
	}
}

func handleProfileFlame(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		p, ok := s.GetProfile(id)
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
}

func handleProfileRaw(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		p, ok := s.GetProfile(id)
		if !ok {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}

		format := r.URL.Query().Get("format")

		switch format {
		case "csv":
			// Export as CSV
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", strconv.Quote(p.Name)))

			writer := csv.NewWriter(w)
			_ = writer.Write([]string{"Function", "File", "Flat", "Flat%", "Cum", "Cum%"})

			rows, _ := buildTop(p.Profile, 0, "")
			for _, row := range rows {
				_ = writer.Write([]string{
					row.Func,
					row.File,
					strconv.FormatInt(row.Flat, 10),
					fmt.Sprintf("%.2f", row.FlatPercent),
					strconv.FormatInt(row.Cum, 10),
					fmt.Sprintf("%.2f", row.CumPercent),
				})
			}
			writer.Flush()

		case "json":
			// Export as JSON
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", strconv.Quote(p.Name)))

			rows, _ := buildTop(p.Profile, 0, "")
			writeJSON(w, rows)

		default:
			// Raw protobuf
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", strconv.Quote(p.Name)))
			_, _ = w.Write(p.Bytes)
		}
	}
}

func handleCompareProfiles(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id1 := r.URL.Query().Get("p1")
		id2 := r.URL.Query().Get("p2")

		if id1 == "" || id2 == "" {
			http.Error(w, "p1 and p2 parameters required", http.StatusBadRequest)
			return
		}

		p1, ok1 := s.GetProfile(id1)
		p2, ok2 := s.GetProfile(id2)

		if !ok1 || !ok2 {
			http.Error(w, "one or both profiles not found", http.StatusNotFound)
			return
		}

		vi := 0
		if qs := r.URL.Query().Get("valueIndex"); qs != "" {
			if n, err := strconv.Atoi(qs); err == nil {
				vi = n
			}
		}

		result, err := compareProfiles(p1, p2, vi)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, result)
	}
}

func handleFlameDiff(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id1 := r.URL.Query().Get("p1")
		id2 := r.URL.Query().Get("p2")

		if id1 == "" || id2 == "" {
			http.Error(w, "p1 and p2 parameters required", http.StatusBadRequest)
			return
		}

		p1, ok1 := s.GetProfile(id1)
		p2, ok2 := s.GetProfile(id2)

		if !ok1 || !ok2 {
			http.Error(w, "one or both profiles not found", http.StatusNotFound)
			return
		}

		vi := 0
		if qs := r.URL.Query().Get("valueIndex"); qs != "" {
			if n, err := strconv.Atoi(qs); err == nil {
				vi = n
			}
		}

		result, err := buildFlameDiff(p1.Profile, p2.Profile, vi)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		writeJSON(w, result)
	}
}

func handleTimeSeries(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		functionName := r.URL.Query().Get("function")
		points := s.GetTimeSeries(functionName)
		writeJSON(w, points)
	}
}

func handleSearchProfiles(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		profiles := s.SearchProfiles(query)
		writeJSON(w, profiles)
	}
}

func handleUploadBundle(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse multipart form with 100MB max memory
		if err := r.ParseMultipartForm(100 << 20); err != nil {
			http.Error(w, "failed to parse form", http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("bundle")
		if err != nil {
			http.Error(w, "missing bundle file", http.StatusBadRequest)
			return
		}
		defer file.Close()

		// Check size
		if header.Size > maxBundleSize {
			http.Error(w, fmt.Sprintf("bundle too large: %d bytes (max: %d)", header.Size, maxBundleSize), http.StatusRequestEntityTooLarge)
			return
		}

		// Create temp file
		tf, err := os.CreateTemp("", "upload-*.zip")
		if err != nil {
			http.Error(w, "failed to create temp file", http.StatusInternalServerError)
			return
		}
		defer tf.Close()
		defer os.Remove(tf.Name())

		// Copy upload to temp file
		if _, err := io.Copy(tf, file); err != nil {
			http.Error(w, "failed to save upload", http.StatusInternalServerError)
			return
		}

		fi, err := tf.Stat()
		if err != nil {
			http.Error(w, "failed to inspect upload", http.StatusInternalServerError)
			return
		}
		if fi.Size() > maxBundleSize {
			http.Error(w, fmt.Sprintf("bundle too large: %d bytes (max: %d)", fi.Size(), maxBundleSize), http.StatusRequestEntityTooLarge)
			return
		}

		// Load bundle
		if _, err := tf.Seek(0, 0); err != nil {
			http.Error(w, "failed to process upload", http.StatusInternalServerError)
			return
		}

		result := loadBundleFromZip(tf, fi.Size(), header.Filename)

		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusBadRequest)
			return
		}

		s.AddBundle(result.Bundle)

		// Return bundle info with warnings
		response := map[string]interface{}{
			"bundle":   result.Bundle,
			"warnings": result.Warnings,
		}
		writeJSON(w, response)
	}
}

func handlePprofProxy(s *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		id := vars["id"]

		ctx := r.Context()
		target, err := s.ensurePprofTarget(ctx, id)
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
	//go:embed web/dashboards/*.json
	grafanaDashboardsFS embed.FS
)

// Main function
func main() {
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
	store := NewStore(logger)
	if _, err := store.ensureGrafanaBinary(); err != nil {
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

			fi, _ := f.Stat()
			result := loadBundleFromZip(f, fi.Size(), validPath)
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
	r.HandleFunc("/style.css", serveCSS)

	// API endpoints
	r.HandleFunc("/api/bundles", withMetrics("list_bundles", handleListBundles(store))).Methods("GET")
	r.HandleFunc("/api/bundles", withMetrics("upload_bundle", handleUploadBundle(store))).Methods("POST")
	r.HandleFunc("/api/bundles/{id}", withMetrics("get_bundle", handleGetBundle(store))).Methods("GET")
	r.HandleFunc("/api/bundles/{id}/prometheus", withMetrics("prometheus_status", handlePrometheusStatus(store))).Methods("GET")
	r.HandleFunc("/api/bundles/{id}/prometheus/start", withMetrics("prometheus_start", handlePrometheusStart(store))).Methods("POST")
	r.HandleFunc("/api/bundles/{id}/prometheus/stop", withMetrics("prometheus_stop", handlePrometheusStop(store))).Methods("POST")
	r.HandleFunc("/api/profiles/search", withMetrics("search_profiles", handleSearchProfiles(store))).Methods("GET")
	r.HandleFunc("/api/profiles/compare", withMetrics("compare_profiles", handleCompareProfiles(store))).Methods("GET")
	r.HandleFunc("/api/profiles/flamediff", withMetrics("flame_diff", handleFlameDiff(store))).Methods("GET")
	r.HandleFunc("/api/profiles/timeseries", withMetrics("time_series", handleTimeSeries(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/summary", withMetrics("profile_summary", handleProfileSummary(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/top", withMetrics("profile_top", handleProfileTop(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/flame", withMetrics("profile_flame", handleProfileFlame(store))).Methods("GET")
	r.HandleFunc("/api/profiles/{id}/raw", withMetrics("profile_raw", handleProfileRaw(store))).Methods("GET")

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
		slog.Int("bundles", len(store.bundles)))

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
	store.promMu.Lock()
	for id := range store.promInstances {
		store.stopPrometheusLocked(id)
	}
	store.promMu.Unlock()

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", slog.String("error", err.Error()))
	}
}
