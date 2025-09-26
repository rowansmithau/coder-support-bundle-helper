package main

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
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

	_ "embed"

	"github.com/google/pprof/profile"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Constants and configuration
const (
	maxBundleSize     = 10 << 30 // 10GB
	maxProfileSize    = 1 << 30  // 1GB
	maxConcurrentOps  = 10
	pprofTimeout      = 30 * time.Minute
	defaultListenAddr = "127.0.0.1:6969"
	maxGzipLayers     = 5
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
}

type Bundle struct {
	ID       string           `json:"id"`
	Name     string           `json:"name"`
	Created  time.Time        `json:"created"`
	Profiles []*StoredProfile `json:"profiles"`
	Warnings []string         `json:"warnings,omitempty"`
	Path     string           `json:"path"`
	Metadata *BundleMetadata  `json:"metadata,omitempty"`
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
}

type HealthStatus struct {
	Healthy   bool       `json:"healthy"`
	Severity  string     `json:"severity"`
	Warnings  []string   `json:"warnings,omitempty"`
	Timestamp *time.Time `json:"timestamp,omitempty"`
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
}

type pprofInstance struct {
	URL       *url.URL
	Process   *exec.Cmd
	Cancel    context.CancelFunc
	TempFile  string
	CreatedAt time.Time
}

func NewStore(logger *slog.Logger) *Store {
	return &Store{
		bundles:      make(map[string]*Bundle),
		profiles:     make(map[string]*StoredProfile),
		pprofTargets: make(map[string]*pprofInstance),
		semaphore:    make(chan struct{}, maxConcurrentOps),
		logger:       logger,
	}
}

func (s *Store) AddBundle(b *Bundle) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, ok := s.bundles[b.ID]; ok {
		for _, p := range existing.Profiles {
			delete(s.profiles, p.ID)
		}
	}
	s.bundles[b.ID] = b
	for _, p := range b.Profiles {
		p.BundleID = b.ID
		s.profiles[p.ID] = p
	}
	bundlesLoaded.Inc()
	s.logger.Info("bundle added",
		slog.String("id", b.ID),
		slog.String("name", b.Name),
		slog.Int("profiles", len(b.Profiles)))
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
			warning := fmt.Sprintf("failed to open %s: %v", f.Name, err)
			result.Warnings = append(result.Warnings, warning)
			continue
		}

		content, err := io.ReadAll(rc)
		_ = rc.Close()
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
		profilesAnalyzed.Inc()
	}

	if len(profs) == 0 {
		result.Warnings = append(result.Warnings, "No pprof profiles found under pprof/ in the zip")
		b.Profiles = []*StoredProfile{}
	} else {
		sort.Slice(profs, func(i, j int) bool { return profs[i].Name < profs[j].Name })
		b.Profiles = profs
	}
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

							// Parse data rows (skip header)
							for i := 1; i < len(lines); i++ {
								line := strings.TrimSpace(lines[i])
								if line == "" {
									continue
								}

								// Split by multiple spaces (table columns are separated by multiple spaces)
								fields := regexp.MustCompile(`\s{2,}`).Split(line, -1)
								if len(fields) >= 5 {
									// Clean up fields
									for j := range fields {
										fields[j] = strings.TrimSpace(fields[j])
									}

									// Extract key information
									licenseInfo["id"] = fields[0]
									licenseInfo["uuid"] = fields[1]
									if len(fields) > 2 {
										licenseInfo["uploaded_at"] = fields[2]
									}
									if len(fields) > 3 {
										licenseInfo["features"] = fields[3]
									}
									if len(fields) > 4 {
										expiresAt := fields[4]
										licenseInfo["expires_at"] = expiresAt

										// Check if license is expired
										if expTime, err := time.Parse(time.RFC3339, expiresAt); err == nil {
											if time.Now().Before(expTime) {
												metadata.LicenseValid = true
												licenseInfo["valid"] = true
												licenseInfo["expired"] = false
											} else {
												metadata.LicenseValid = false
												licenseInfo["valid"] = false
												licenseInfo["expired"] = true
												*warnings = append(*warnings, fmt.Sprintf("License expired on %s", expiresAt))
											}
										}
									}
									if len(fields) > 5 {
										licenseInfo["trial"] = fields[5]
									}

									break // Only process first data row
								}
							}

							// Convert to JSON for storage
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

	return capturedAt
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
	if _, err := exec.LookPath("dot"); err != nil {
		logger.Error("Graphviz 'dot' not found in PATH",
			slog.String("install_macos", "brew install graphviz"),
			slog.String("install_debian", "sudo apt-get install graphviz"),
			slog.String("install_fedora", "sudo dnf install graphviz"))
		os.Exit(1)
	}

	// Create store
	store := NewStore(logger)

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

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("shutdown error", slog.String("error", err.Error()))
	}
}
