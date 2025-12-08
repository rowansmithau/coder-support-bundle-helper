package parser

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/util"
)

// ParseBundleMetadata parses metadata from various files in the bundle.
func ParseBundleMetadata(zr *zip.Reader, metadata *models.BundleMetadata, warnings *[]string) *time.Time {
	if metadata == nil {
		return nil
	}

	var buildInfoRaw []byte
	var capturedAt *time.Time

	// Parse deployment/buildinfo.json
	if buildinfoFile := util.FindSibling(zr, "deployment/buildinfo.json"); buildinfoFile != nil {
		if content, err := util.ReadZipFile(buildinfoFile); err == nil {
			content = bytes.TrimSpace(content)
			buildInfoRaw = append([]byte(nil), content...)
			if len(content) > 0 {
				metadata.BuildInfo = json.RawMessage(content)
			}
			var buildInfo map[string]interface{}
			if err := json.Unmarshal(content, &buildInfo); err == nil {
				if deploymentID, ok := buildInfo["deployment_id"].(string); ok {
					deploymentID = strings.TrimSpace(deploymentID)
					if deploymentID != "" {
						metadata.DeploymentID = deploymentID
					}
				}
				if version, ok := buildInfo["version"].(string); ok {
					version = strings.TrimSpace(version)
					if version != "" {
						metadata.Version = version
					}
				}
				for _, key := range []string{"dashboard_url", "dashboardUrl", "dashboardURL"} {
					if metadata.DashboardURL == "" {
						if d, ok := buildInfo[key].(string); ok {
							if d = strings.TrimSpace(d); d != "" {
								metadata.DashboardURL = d
								break
							}
						}
					}
				}
				if extURL, ok := buildInfo["external_url"].(string); ok && metadata.Version == "" {
					if strings.Contains(extURL, "/commit/") {
						parts := strings.Split(extURL, "/commit/")
						if len(parts) > 1 && len(parts[1]) >= 8 {
							metadata.Version = "commit:" + parts[1][:8]
						}
					}
				}
			} else {
				*warnings = append(*warnings, fmt.Sprintf("deployment/buildinfo.json is not valid JSON: %v", err))
			}
		}
	}

	// Parse license-status.txt
	if licenseFile := util.FindSibling(zr, "license-status.txt"); licenseFile != nil {
		if content, err := util.ReadZipFile(licenseFile); err == nil {
			metadata.LicenseFound = true
			trimmedContent := bytes.TrimSpace(content)
			metadata.LicenseStatusRaw = string(trimmedContent)
			if len(trimmedContent) > 0 {
				if trimmedContent[0] == '{' || trimmedContent[0] == '[' {
					var licenseData map[string]interface{}
					if err := json.Unmarshal(trimmedContent, &licenseData); err == nil {
						metadata.LicenseStatus = json.RawMessage(trimmedContent)
						if _, hasExtURL := licenseData["external_url"]; hasExtURL {
							metadata.LicenseValid = true
						}
						if v, ok := licenseData["version"].(string); ok && metadata.Version == "" {
							v = strings.TrimSpace(v)
							if v != "" {
								metadata.Version = v
							}
						}
						if d, ok := licenseData["dashboard_url"].(string); ok && metadata.DashboardURL == "" {
							if d = strings.TrimSpace(d); d != "" {
								metadata.DashboardURL = d
							}
						}
						if d, ok := licenseData["deployment_id"].(string); ok && metadata.DeploymentID == "" {
							metadata.DeploymentID = d
						}
					} else {
						*warnings = append(*warnings, fmt.Sprintf("license-status.txt appears to be malformed JSON: %v", err))
						metadata.LicenseStatus = json.RawMessage(fmt.Sprintf(`{"error": "malformed", "raw": %q}`, string(trimmedContent)))
						metadata.LicenseValid = false
					}
				} else {
					textContent := string(trimmedContent)
					lines := strings.Split(textContent, "\n")
					if len(lines) >= 2 && strings.Contains(lines[0], "UUID") && strings.Contains(lines[0], "EXPIRES AT") {
						parseLicenseTable(lines, metadata, warnings)
					} else {
						lowerContent := strings.ToLower(textContent)
						if strings.Contains(lowerContent, "invalid") ||
							strings.Contains(lowerContent, "inactive") ||
							strings.Contains(lowerContent, "expired") ||
							strings.Contains(lowerContent, "error") ||
							strings.Contains(lowerContent, "no license") {
							metadata.LicenseValid = false
							*warnings = append(*warnings, fmt.Sprintf("License appears to be invalid: %s", textContent))
						} else {
							metadata.LicenseValid = true
						}
						metadata.LicenseStatus = json.RawMessage(fmt.Sprintf(`{"status": %q, "type": "plaintext"}`, textContent))
					}
				}
			}
		}
	}

	// Parse network/tailnet_debug.html for embedded build info
	if tailnetFile := util.FindSibling(zr, "network/tailnet_debug.html"); tailnetFile != nil {
		if content, err := util.ReadZipFile(tailnetFile); err == nil {
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
							if JSONBytesEqual(decodedTrim, buildInfoTrim) {
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
	}

	// Parse health report
	if healthFile := util.FindSibling(zr, "deployment/health.json"); healthFile != nil {
		if content, err := util.ReadZipFile(healthFile); err == nil {
			status, err := ParseHealthReport(content)
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
	}

	// Try to get timestamp from CLI logs
	if capturedAt == nil {
		for _, f := range zr.File {
			if !strings.HasSuffix(f.Name, "cli_logs.txt") {
				continue
			}
			content, err := util.ReadZipFile(f)
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

	ParseNetworkInfo(zr, metadata, warnings)

	return capturedAt
}

func parseLicenseTable(lines []string, metadata *models.BundleMetadata, warnings *[]string) {
	licenseInfo := make(map[string]interface{})
	licenseInfo["type"] = "table"
	licenseInfo["raw"] = strings.Join(lines, "\n")

	licenses := make([]map[string]interface{}, 0)
	validFound := false

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
			}
		}
		if len(fields) > 5 {
			entry["trial"] = strings.ToLower(fields[5]) == "true"
		}

		licenses = append(licenses, entry)
	}

	licenseInfo["licenses"] = licenses
	metadata.LicenseValid = validFound

	if jsonBytes, err := json.Marshal(licenseInfo); err == nil {
		metadata.LicenseStatus = json.RawMessage(jsonBytes)
	}
}

// JSONBytesEqual compares two JSON byte slices for semantic equality.
func JSONBytesEqual(a, b []byte) bool {
	var va, vb interface{}
	if err := json.Unmarshal(a, &va); err != nil {
		return false
	}
	if err := json.Unmarshal(b, &vb); err != nil {
		return false
	}

	ab, err := json.Marshal(va)
	if err != nil {
		return false
	}
	bb, err := json.Marshal(vb)
	if err != nil {
		return false
	}
	return string(ab) == string(bb)
}

// ParseHealthReport parses a health report JSON.
func ParseHealthReport(content []byte) (*models.HealthStatus, error) {
	var base struct {
		Time     string `json:"time"`
		Healthy  bool   `json:"healthy"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(content, &base); err != nil {
		return nil, err
	}

	var raw interface{}
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

	status := &models.HealthStatus{
		Healthy:  base.Healthy,
		Severity: strings.ToLower(base.Severity),
		Warnings: warnings,
	}

	if base.Time != "" {
		if t, err := time.Parse(time.RFC3339Nano, base.Time); err == nil {
			status.Timestamp = &t
		}
	}

	if rawMap, ok := raw.(map[string]interface{}); ok {
		keys := make([]string, 0, len(rawMap))
		for key := range rawMap {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		components := make([]models.HealthComponent, 0)
		notes := make([]string, 0)

		for _, key := range keys {
			value := rawMap[key]
			if key == "time" || key == "healthy" || key == "severity" || key == "coder_version" {
				continue
			}

			comp, note := buildComponent(key, value, warnings)
			if comp != nil {
				components = append(components, *comp)
			}
			if note != "" {
				notes = append(notes, note)
			}
		}

		if len(components) > 0 {
			status.Components = components
		}
		if len(notes) > 0 {
			status.Notes = util.DedupeStrings(notes)
		}
	}

	return status, nil
}

func buildComponent(key string, value interface{}, existingWarnings []string) (*models.HealthComponent, string) {
	m, ok := value.(map[string]interface{})
	if !ok {
		return nil, ""
	}

	comp := &models.HealthComponent{
		Name:     util.HumanizeKey(key),
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

	if len(messages) > 0 {
		comp.Messages = util.DedupeStrings(messages)
	}

	return comp, ""
}

func getBool(v interface{}) bool {
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

func collectWarnings(value interface{}, seen map[string]struct{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		for _, val := range v {
			collectWarnings(val, seen)
		}
		if warns, ok := v["warnings"]; ok {
			for _, w := range flattenMessages(warns) {
				seen[w] = struct{}{}
			}
		}
	case []interface{}:
		for _, item := range v {
			collectWarnings(item, seen)
		}
	}
}

func flattenMessages(value interface{}) []string {
	var out []string
	var visit func(v interface{})
	visit = func(v interface{}) {
		switch val := v.(type) {
		case string:
			s := strings.TrimSpace(val)
			if s != "" {
				out = append(out, s)
			}
		case []interface{}:
			for _, item := range val {
				visit(item)
			}
		case map[string]interface{}:
			message := ""
			if msg, ok := val["message"]; ok {
				message = strings.TrimSpace(fmt.Sprint(msg))
			}
			if message == "" {
				for _, key := range []string{"detail", "description", "summary", "error", "reason"} {
					if msg, ok := val[key]; ok {
						message = strings.TrimSpace(fmt.Sprint(msg))
						if message != "" {
							break
						}
					}
				}
			}
			// Prepend code if present (e.g., "EWP04: message...")
			if code, ok := val["code"]; ok {
				codeStr := strings.TrimSpace(fmt.Sprint(code))
				if codeStr != "" && message != "" {
					message = codeStr + ": " + message
				}
			}
			if message != "" {
				out = append(out, message)
			} else {
				pretty := strings.TrimSpace(fmt.Sprint(val))
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
