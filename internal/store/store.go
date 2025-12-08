// Package store provides the in-memory data store for bundles and profiles,
// along with Prometheus, Grafana, and pprof instance management.
package store

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/common/model"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
)

func init() {
	// Set the validation scheme to legacy mode to allow parsing older Prometheus metrics.
	// This must be set before any metric parsing occurs.
	model.NameValidationScheme = model.LegacyValidation
}

// EnsurePrometheusValidation ensures the validation scheme is set.
// This is called before parsing metrics to guard against init() ordering issues.
func EnsurePrometheusValidation() {
	model.NameValidationScheme = model.LegacyValidation
}

const (
	maxConcurrentOps = 10
	pprofTimeout     = 30 * time.Minute
)

// Store holds bundles and profiles in memory.
type Store struct {
	mu       sync.RWMutex
	bundles  map[string]*models.Bundle
	profiles map[string]*models.StoredProfile
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

	grafMu         sync.Mutex
	grafInstance   *GrafanaInstance
	grafBaseDir    string
	grafBinary     string
	grafHome       string
	grafFolderURL  string
	grafRangeStart time.Time
	grafRangeEnd   time.Time

	// Embedded dashboards filesystem (injected from main)
	dashboardsFS fs.FS
}

type pprofInstance struct {
	URL       *url.URL
	Process   *exec.Cmd
	Cancel    context.CancelFunc
	TempFile  string
	CreatedAt time.Time
}

// PrometheusInstance represents a running Prometheus server.
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

// GrafanaInstance represents a running Grafana server.
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

// New creates a new Store.
func New(logger *slog.Logger, dashboardsFS fs.FS) *Store {
	promBase := filepath.Join(os.TempDir(), "coder-support-prom")
	grafBase := filepath.Join(os.TempDir(), "coder-support-grafana")
	return &Store{
		bundles:       make(map[string]*models.Bundle),
		profiles:      make(map[string]*models.StoredProfile),
		logger:        logger,
		pprofTargets:  make(map[string]*pprofInstance),
		semaphore:     make(chan struct{}, maxConcurrentOps),
		promInstances: make(map[string]*PrometheusInstance),
		promBaseDir:   promBase,
		grafBaseDir:   grafBase,
		dashboardsFS:  dashboardsFS,
	}
}

// AddBundle adds a bundle to the store.
func (s *Store) AddBundle(b *models.Bundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bundles[b.ID] = b

	// Index profiles
	for _, p := range b.Profiles {
		s.profiles[p.ID] = p
	}

	// Start Prometheus in background if we have snapshots
	if len(b.Prometheus) > 0 {
		go func(bundleID string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			s.logger.Info("auto-starting Prometheus for bundle",
				slog.String("bundleId", bundleID),
				slog.Int("snapshots", len(b.Prometheus)))

			inst, err := s.StartPrometheus(ctx, bundleID)
			if err != nil {
				s.logger.Error("failed to auto-start Prometheus",
					slog.String("bundleId", bundleID),
					slog.String("error", err.Error()))
				return
			}

			s.logger.Info("Prometheus ready for bundle",
				slog.String("bundleId", bundleID),
				slog.String("url", inst.URL),
				slog.String("graphUrl", inst.GraphURL))
		}(b.ID)
	}
}

// SetGrafanaLinks sets Grafana links on all bundles.
func (s *Store) SetGrafanaLinks(baseURL, folderURL string, start, end time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.bundles {
		b.GrafanaURL = buildGrafanaURLWithRange(baseURL, true, start, end)
		b.GrafanaFolderURL = folderURL
	}
}

// GetBundle returns a bundle by ID.
func (s *Store) GetBundle(id string) (*models.Bundle, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.bundles[id]
	return b, ok
}

// GetAllBundles returns all bundles sorted by name.
func (s *Store) GetAllBundles() []*models.Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*models.Bundle, 0, len(s.bundles))
	for _, b := range s.bundles {
		result = append(result, b)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}

// GetProfile returns a profile by ID.
func (s *Store) GetProfile(id string) (*models.StoredProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.profiles[id]
	return p, ok
}

// SearchProfiles searches profiles by query.
func (s *Store) SearchProfiles(query string) []*models.StoredProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if query == "" {
		result := make([]*models.StoredProfile, 0, len(s.profiles))
		for _, p := range s.profiles {
			result = append(result, p)
		}
		return result
	}

	query = strings.ToLower(query)
	var results []*models.StoredProfile

	for _, p := range s.profiles {
		if strings.Contains(strings.ToLower(p.Name), query) ||
			strings.Contains(strings.ToLower(p.Path), query) ||
			strings.Contains(strings.ToLower(p.Group), query) {
			results = append(results, p)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Name < results[j].Name
	})

	return results
}

// CleanupOldProfiles removes old pprof instances.
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
					_ = os.Remove(inst.TempFile)
					delete(s.pprofTargets, id)
				}
			}
			s.pprofMu.Unlock()
		}
	}
}

// GetTimeSeries returns time series data for a function name.
func (s *Store) GetTimeSeries(functionName string) []models.TimeSeriesPoint {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var points []models.TimeSeriesPoint

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
				points = append(points, models.TimeSeriesPoint{
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

// GetPrometheusInstance returns the Prometheus instance for a bundle.
func (s *Store) GetPrometheusInstance(bundleID string) *PrometheusInstance {
	s.promMu.Lock()
	defer s.promMu.Unlock()
	return s.promInstances[bundleID]
}

// EnsurePprofTarget ensures a pprof server is running for a profile.
func (s *Store) EnsurePprofTarget(ctx context.Context, id string) (*url.URL, error) {
	// Check if already running
	s.pprofMu.RLock()
	if inst := s.pprofTargets[id]; inst != nil {
		s.pprofMu.RUnlock()
		return inst.URL, nil
	}
	s.pprofMu.RUnlock()

	// Get profile
	p, ok := s.GetProfile(id)
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", id)
	}

	// Acquire semaphore
	select {
	case s.semaphore <- struct{}{}:
		defer func() { <-s.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Double-check after acquiring semaphore
	s.pprofMu.Lock()
	if inst := s.pprofTargets[id]; inst != nil {
		s.pprofMu.Unlock()
		return inst.URL, nil
	}

	// Write profile to temp file
	tmpFile, err := os.CreateTemp("", "pprof-*.pb.gz")
	if err != nil {
		s.pprofMu.Unlock()
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	if _, err := tmpFile.Write(p.Bytes); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		s.pprofMu.Unlock()
		return nil, fmt.Errorf("write profile: %w", err)
	}
	_ = tmpFile.Close()

	// Find free port
	addr, err := chooseFreeAddress()
	if err != nil {
		_ = os.Remove(tmpFile.Name())
		s.pprofMu.Unlock()
		return nil, fmt.Errorf("find free port: %w", err)
	}

	// Start pprof web server
	pprofCtx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(pprofCtx, "go", "tool", "pprof", "-http="+addr, tmpFile.Name())
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		cancel()
		_ = os.Remove(tmpFile.Name())
		s.pprofMu.Unlock()
		return nil, fmt.Errorf("start pprof: %w", err)
	}

	targetURL, _ := url.Parse("http://" + addr)

	s.pprofTargets[id] = &pprofInstance{
		URL:       targetURL,
		Process:   cmd,
		Cancel:    cancel,
		TempFile:  tmpFile.Name(),
		CreatedAt: time.Now(),
	}
	s.pprofMu.Unlock()

	// Wait for server to be ready
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(targetURL.String())
		if err == nil {
			_ = resp.Body.Close()
			s.logger.Info("pprof server ready", slog.String("id", id), slog.String("url", targetURL.String()))
			return targetURL, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return targetURL, nil
}

func chooseFreeAddress() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr, nil
}

func (s *Store) streamCommandOutput(r io.Reader, component, identifier, stream string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s.logger.Debug(fmt.Sprintf("%s output", component),
			slog.String("id", identifier),
			slog.String("stream", stream),
			slog.String("line", scanner.Text()))
	}
}
