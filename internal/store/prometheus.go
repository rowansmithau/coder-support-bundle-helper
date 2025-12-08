package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"log/slog"
	"net/url"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/storage"
	"github.com/prometheus/prometheus/tsdb"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
)



// StartPrometheus starts a Prometheus instance for a bundle.
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
		if _, err := s.ensureGrafana(inst.URL, inst.RangeStart, inst.RangeEnd); err != nil {
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

	if _, err := s.ensureGrafana(inst.URL, startRange, endRange); err != nil {
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
				if _, err := s.ensureGrafana(nextProm.URL, nextProm.RangeStart, nextProm.RangeEnd); err != nil {
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



// StopAllPrometheus stops all running Prometheus instances.
func (s *Store) StopAllPrometheus() {
	s.promMu.Lock()
	defer s.promMu.Unlock()
	for id := range s.promInstances {
		s.stopPrometheusLocked(id)
	}
}
// StopPrometheus stops a Prometheus instance.
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
			if _, err := s.ensureGrafana(nextProm.URL, nextProm.RangeStart, nextProm.RangeEnd); err != nil {
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
		return s.promBinary, nil
	}
	path, err := exec.LookPath("prometheus")
	if err != nil {
		return "", fmt.Errorf("prometheus binary not found (install with: go install github.com/prometheus/prometheus/cmd/prometheus@latest)")
	}
	s.promBinary = path
	return path, nil
}

func (s *Store) buildTSDBFromSnapshots(bundleID string, snapshots []*models.PrometheusSnapshot, dataDir string) (time.Time, time.Time, error) {
	promLogger := promslog.NewNopLogger()

	db, err := tsdb.Open(dataDir, promLogger, nil, &tsdb.Options{
		RetentionDuration:              int64(7 * 24 * time.Hour / time.Millisecond),
		MinBlockDuration:               int64(2 * time.Hour / time.Millisecond),
		MaxBlockDuration:               int64(24 * time.Hour / time.Millisecond),
		EnableNativeHistograms:         true,
		OutOfOrderTimeWindow:           int64(24 * time.Hour / time.Millisecond),
		EnableOverlappingCompaction:    true,
		OutOfOrderCapMax:               32,
		EnableDelayedCompaction:        true,
		CompactionDelayMaxPercent:      50,
		EnableMemorySnapshotOnShutdown: false,
	}, nil)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("open tsdb: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			s.logger.Error("close tsdb", slog.String("error", err.Error()))
		}
	}()

	var minTs, maxTs int64
	totalSamples := 0

	for _, snap := range snapshots {
		app := db.Appender(context.Background())
		ts := snap.CreatedAt.UnixMilli()

		if minTs == 0 || ts < minTs {
			minTs = ts
		}
		if ts > maxTs {
			maxTs = ts
		}

		parser := expfmt.NewTextParser(model.LegacyValidation)
		families, err := parser.TextToMetricFamilies(strings.NewReader(string(snap.Content)))
		if err != nil {
			s.logger.Warn("parse prometheus snapshot",
				slog.String("bundle", bundleID),
				slog.Time("time", snap.CreatedAt),
				slog.String("error", err.Error()))
			continue
		}

		for name, fam := range families {
			for _, m := range fam.Metric {
				n, err := s.appendMetricSamples(app, name, fam.GetType(), m, ts, nil)
				if err != nil {
					s.logger.Debug("append metric samples",
						slog.String("name", name),
						slog.String("error", err.Error()))
				}
				totalSamples += n
			}
		}

		if err := app.Commit(); err != nil {
			return time.Time{}, time.Time{}, fmt.Errorf("commit samples: %w", err)
		}
	}

	s.logger.Info("built tsdb from snapshots",
		slog.String("bundle", bundleID),
		slog.Int("snapshots", len(snapshots)),
		slog.Int("samples", totalSamples),
		slog.Time("start", time.UnixMilli(minTs)),
		slog.Time("end", time.UnixMilli(maxTs)))

	return time.UnixMilli(minTs), time.UnixMilli(maxTs), nil
}

func (s *Store) appendMetricSamples(app storage.Appender, name string, famType dto.MetricType, metric *dto.Metric, ts int64, extra map[string]string) (int, error) {
	count := 0
	switch famType {
	case dto.MetricType_COUNTER:
		if metric.Counter != nil {
			n, err := addSample(app, metric, name, metric.Counter.GetValue(), ts, extra)
			count += n
			if err != nil {
				return count, err
			}
		}
	case dto.MetricType_GAUGE:
		if metric.Gauge != nil {
			n, err := addSample(app, metric, name, metric.Gauge.GetValue(), ts, extra)
			count += n
			if err != nil {
				return count, err
			}
		}
	case dto.MetricType_SUMMARY:
		if metric.Summary != nil {
			n, err := addSample(app, metric, name+"_sum", metric.Summary.GetSampleSum(), ts, extra)
			count += n
			if err != nil {
				return count, err
			}
			n, err = addSample(app, metric, name+"_count", float64(metric.Summary.GetSampleCount()), ts, extra)
			count += n
			if err != nil {
				return count, err
			}
			for _, q := range metric.Summary.Quantile {
				qExtra := cloneExtra(extra)
				qExtra["quantile"] = formatFloat(q.GetQuantile())
				n, err := addSample(app, metric, name, q.GetValue(), ts, qExtra)
				count += n
				if err != nil {
					return count, err
				}
			}
		}
	case dto.MetricType_HISTOGRAM:
		if metric.Histogram != nil {
			n, err := addSample(app, metric, name+"_sum", metric.Histogram.GetSampleSum(), ts, extra)
			count += n
			if err != nil {
				return count, err
			}
			n, err = addSample(app, metric, name+"_count", float64(metric.Histogram.GetSampleCount()), ts, extra)
			count += n
			if err != nil {
				return count, err
			}
			for _, b := range metric.Histogram.Bucket {
				bExtra := cloneExtra(extra)
				bExtra["le"] = formatLE(b.GetUpperBound())
				n, err := addSample(app, metric, name+"_bucket", float64(b.GetCumulativeCount()), ts, bExtra)
				count += n
				if err != nil {
					return count, err
				}
			}
			infExtra := cloneExtra(extra)
			infExtra["le"] = "+Inf"
			n, err = addSample(app, metric, name+"_bucket", float64(metric.Histogram.GetSampleCount()), ts, infExtra)
			count += n
			if err != nil {
				return count, err
			}
		}
	case dto.MetricType_UNTYPED:
		if metric.Untyped != nil {
			n, err := addSample(app, metric, name, metric.Untyped.GetValue(), ts, extra)
			count += n
			if err != nil {
				return count, err
			}
		}
	}
	return count, nil
}

func addSample(app storage.Appender, metric *dto.Metric, name string, value float64, ts int64, extra map[string]string) (int, error) {
	lbls := labels.NewBuilder(labels.EmptyLabels())
	lbls.Set(model.MetricNameLabel, name)
	for _, lp := range metric.Label {
		lbls.Set(lp.GetName(), lp.GetValue())
	}
	for k, v := range extra {
		lbls.Set(k, v)
	}
	_, err := app.Append(0, lbls.Labels(), ts, value)
	if err != nil {
		return 0, err
	}
	return 1, nil
}

func cloneExtra(src map[string]string) map[string]string {
	if src == nil {
		return make(map[string]string)
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func formatFloat(v float64) string {
	return fmt.Sprintf("%g", v)
}

func formatLE(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%.1f", v)
	}
	return fmt.Sprintf("%g", v)
}

func prometheusRangeString(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func buildPrometheusGraphURL(baseURL string, start, end time.Time) string {
	// Use 15-minute range or data range, whichever is larger
	dataRange := end.Sub(start)
	displayRange := dataRange
	if displayRange < 15*time.Minute {
		displayRange = 15 * time.Minute
	}

	// Center the view around the data
	midpoint := start.Add(dataRange / 2)
	viewStart := midpoint.Add(-displayRange / 2)
	viewEnd := midpoint.Add(displayRange / 2)

	// Add padding
	padding := displayRange / 10
	viewStart = viewStart.Add(-padding)
	viewEnd = viewEnd.Add(padding)

	return fmt.Sprintf("%s/query?g0.end_input=%s&g0.expr=&g0.range_input=%s&g0.tab=0",
		baseURL,
		url.QueryEscape(viewEnd.UTC().Format("2006-01-02 15:04:05")),
		prometheusRangeString(displayRange+2*padding))
}
