package store

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func (s *Store) writeGrafanaDashboards(dir string, start, end time.Time) error {
	dashDir := filepath.Join(dir, "dashboards")
	if err := os.MkdirAll(dashDir, 0o755); err != nil {
		return fmt.Errorf("create dashboard dir: %w", err)
	}

	files, err := fs.Glob(s.dashboardsFS, "web/dashboards/*.json")
	if err != nil {
		return fmt.Errorf("glob dashboards: %w", err)
	}

	for _, name := range files {
		data, err := fs.ReadFile(s.dashboardsFS, name)
		if err != nil {
			return fmt.Errorf("read dashboard %s: %w", name, err)
		}
		modified, err := s.dashboardWithTimeRange(data, start, end)
		if err != nil {
			s.logger.Warn("failed to set time range in dashboard", slog.String("name", name), slog.String("error", err.Error()))
			modified = data
		}
		outPath := filepath.Join(dashDir, filepath.Base(name))
		if err := os.WriteFile(outPath, modified, 0o644); err != nil {
			return fmt.Errorf("write dashboard %s: %w", name, err)
		}
	}

	return nil
}

func (s *Store) dashboardWithTimeRange(data []byte, start, end time.Time) ([]byte, error) {
	var dash map[string]interface{}
	if err := json.Unmarshal(data, &dash); err != nil {
		return nil, err
	}

	// Set time range
	dash["time"] = map[string]interface{}{
		"from": start.UTC().Format(time.RFC3339),
		"to":   end.UTC().Format(time.RFC3339),
	}

	// Remove refresh interval for historical data
	dash["refresh"] = ""

	return json.MarshalIndent(dash, "", "  ")
}

// EnsureGrafanaBinary checks that grafana-server is available.
func (s *Store) EnsureGrafanaBinary() (string, error) {
	if s.grafBinary != "" {
		return s.grafBinary, nil
	}

	// Try common locations
	candidates := []string{
		"grafana-server",
		"grafana",
		"/usr/local/bin/grafana-server",
		"/opt/homebrew/bin/grafana-server",
		"/usr/sbin/grafana-server",
	}

	for _, c := range candidates {
		path, err := exec.LookPath(c)
		if err == nil {
			s.grafBinary = path
			home, err := detectGrafanaHome(path)
			if err != nil {
				s.logger.Warn("failed to detect grafana home", slog.String("error", err.Error()))
			} else {
				s.grafHome = home
			}
			return path, nil
		}
	}

	return "", fmt.Errorf("grafana-server binary not found (install Grafana or set PATH)")
}

func detectGrafanaHome(bin string) (string, error) {
	// Try to find homepath from binary location
	// Common layouts:
	// /opt/homebrew/bin/grafana-server -> /opt/homebrew/share/grafana
	// /usr/sbin/grafana-server -> /usr/share/grafana
	// /usr/local/bin/grafana-server -> /usr/local/share/grafana

	binDir := filepath.Dir(bin)
	parent := filepath.Dir(binDir)

	candidates := []string{
		filepath.Join(parent, "share", "grafana"),
		"/usr/share/grafana",
		"/opt/homebrew/share/grafana",
		"/usr/local/share/grafana",
	}

	// Check environment variable first
	if envHome := strings.TrimSpace(os.Getenv("GF_PATHS_HOME")); envHome != "" {
		if _, err := os.Stat(envHome); err == nil {
			return envHome, nil
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}

	return "", fmt.Errorf("could not detect grafana home directory")
}

func (s *Store) ensureGrafana(promURL string, start, end time.Time) (*GrafanaInstance, error) {
	s.grafMu.Lock()
	defer s.grafMu.Unlock()
	return s.ensureGrafanaLocked(promURL, start, end)
}

func (s *Store) ensureGrafanaLocked(promURL string, start, end time.Time) (*GrafanaInstance, error) {
	// If already running with same Prometheus URL, just update time range
	if s.grafInstance != nil && s.grafInstance.cmd != nil && s.grafInstance.cmd.Process != nil {
		if s.grafInstance.PrometheusURL == promURL {
			return s.grafInstance, nil
		}
		// Different Prometheus - need to update datasource
		s.stopGrafanaLocked()
	}

	bin, err := s.EnsureGrafanaBinary()
	if err != nil {
		return nil, err
	}

	baseDir := filepath.Join(s.grafBaseDir, "instance")
	if err := os.RemoveAll(baseDir); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("reset grafana dir: %w", err)
	}

	// Create directory structure
	dirs := []string{
		filepath.Join(baseDir, "conf", "provisioning", "datasources"),
		filepath.Join(baseDir, "conf", "provisioning", "dashboards"),
		filepath.Join(baseDir, "conf", "provisioning", "notifiers"),
		filepath.Join(baseDir, "conf", "provisioning", "alerting"),
		filepath.Join(baseDir, "conf", "provisioning", "plugins"),
		filepath.Join(baseDir, "data"),
		filepath.Join(baseDir, "logs"),
		filepath.Join(baseDir, "plugins"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return nil, fmt.Errorf("create dir %s: %w", d, err)
		}
	}

	// Write dashboards
	if err := s.writeGrafanaDashboards(baseDir, start, end); err != nil {
		s.logger.Warn("failed to write grafana dashboards", slog.String("error", err.Error()))
	}

	// Write datasource config
	dsConfig := fmt.Sprintf(`apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: %s
    isDefault: true
    editable: false
`, promURL)
	dsPath := filepath.Join(baseDir, "conf", "provisioning", "datasources", "prometheus.yaml")
	if err := os.WriteFile(dsPath, []byte(dsConfig), 0o644); err != nil {
		return nil, fmt.Errorf("write datasource config: %w", err)
	}

	// Write dashboard provisioning config
	dashProvConfig := fmt.Sprintf(`apiVersion: 1
providers:
  - name: 'default'
    orgId: 1
    folder: 'Support Bundle'
    folderUid: 'support-bundle'
    type: file
    disableDeletion: false
    updateIntervalSeconds: 10
    options:
      path: %s
`, filepath.Join(baseDir, "dashboards"))
	dashProvPath := filepath.Join(baseDir, "conf", "provisioning", "dashboards", "default.yaml")
	if err := os.WriteFile(dashProvPath, []byte(dashProvConfig), 0o644); err != nil {
		return nil, fmt.Errorf("write dashboard provisioner config: %w", err)
	}

	addr, err := chooseFreeAddress()
	if err != nil {
		return nil, fmt.Errorf("allocate grafana address: %w", err)
	}

	// Parse address
	host, port := "127.0.0.1", "3000"
	if parts := strings.Split(addr, ":"); len(parts) == 2 {
		host, port = parts[0], parts[1]
	}

	cmdCtx, cancel := context.WithCancel(context.Background())

	args := []string{
		"--config", filepath.Join(s.grafHome, "conf", "defaults.ini"),
		"--homepath", s.grafHome,
	}

	cmd := exec.CommandContext(cmdCtx, bin, args...)
	cmd.Dir = baseDir
	cmd.Env = append(os.Environ(),
		"GF_SERVER_HTTP_ADDR="+host,
		"GF_SERVER_HTTP_PORT="+port,
		"GF_PATHS_DATA="+filepath.Join(baseDir, "data"),
		"GF_PATHS_LOGS="+filepath.Join(baseDir, "logs"),
		"GF_PATHS_PLUGINS="+filepath.Join(baseDir, "plugins"),
		"GF_PATHS_PROVISIONING="+filepath.Join(baseDir, "conf", "provisioning"),
		"GF_SECURITY_ADMIN_USER=admin",
		"GF_SECURITY_ADMIN_PASSWORD=admin",
		"GF_AUTH_ANONYMOUS_ENABLED=true",
		"GF_AUTH_ANONYMOUS_ORG_ROLE=Admin",
		"GF_LOG_MODE=console",
		"GF_LOG_LEVEL=warn",
		"GF_ALERTING_ENABLED=false",
		"GF_UNIFIED_ALERTING_ENABLED=false",
	)

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

	go s.streamCommandOutput(stdout, "grafana", "instance", "stdout")
	go s.streamCommandOutput(stderr, "grafana", "instance", "stderr")

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

	s.grafInstance = inst
	s.grafRangeStart = start
	s.grafRangeEnd = end

	// Get folder URL for dashboards
	folderURL := grafanaFolderBase(inst.URL)
	s.grafFolderURL = folderURL
	s.SetGrafanaLinks(inst.URL, folderURL, start, end)

	go func() {
		err := cmd.Wait()
		if err != nil {
			s.logger.Error("grafana exited", slog.String("error", err.Error()))
		}
		s.grafMu.Lock()
		s.grafInstance = nil
		s.grafMu.Unlock()
		close(done)
	}()

	s.logger.Info("grafana started",
		slog.String("url", inst.URL),
		slog.String("prometheus", promURL),
		slog.String("folder", folderURL))

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
}

// StopGrafana stops the Grafana instance.
func (s *Store) StopGrafana() {
	s.grafMu.Lock()
	s.stopGrafanaLocked()
	s.grafMu.Unlock()
}

func grafanaFolderBase(base string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base + "/dashboards/f/support-bundle"
	}
	u.Path = "/dashboards/f/support-bundle"
	return u.String()
}

func buildGrafanaURLWithRange(raw string, ensureOrg bool, start, end time.Time) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	q := u.Query()
	q.Set("from", fmt.Sprintf("%d", start.UnixMilli()))
	q.Set("to", fmt.Sprintf("%d", end.UnixMilli()))
	if ensureOrg && q.Get("orgId") == "" {
		q.Set("orgId", "1")
	}
	u.RawQuery = q.Encode()

	return u.String()
}
