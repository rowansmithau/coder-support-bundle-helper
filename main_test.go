package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/pprof/profile"
)

func buildTestZip(t *testing.T, files map[string][]byte) (*bytes.Reader, int64) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	data := buf.Bytes()
	return bytes.NewReader(data), int64(len(data))
}

func makeTestProfile(t *testing.T) []byte {
	t.Helper()
	p := &profile.Profile{
		SampleType: []*profile.ValueType{{Type: "cpu", Unit: "nanoseconds"}},
		Sample: []*profile.Sample{{
			Value:    []int64{1},
			Location: []*profile.Location{{ID: 1}},
		}},
		Location: []*profile.Location{{
			ID: 1,
			Line: []profile.Line{{
				Function: &profile.Function{ID: 1, Name: "main.main", Filename: "main.go"},
			}},
		}},
		Function:      []*profile.Function{{ID: 1, Name: "main.main", Filename: "main.go"}},
		TimeNanos:     time.Now().UnixNano(),
		DurationNanos: int64(time.Millisecond),
	}
	var buf bytes.Buffer
	if err := p.WriteUncompressed(&buf); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	return buf.Bytes()
}

func TestLoadBundle_ValidLicense(t *testing.T) {
	license := []byte(`{"external_url":"https://example.com","version":"1.0.0","dashboard_url":"https://dash","deployment_id":"dep-1234"}`)
	reader, size := buildTestZip(t, map[string][]byte{
		"license-status.txt": license,
	})

	result := loadBundleFromZip(reader, size, "bundle.zip")
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Bundle.Metadata.LicenseFound {
		t.Fatalf("expected license to be found")
	}
	if !result.Bundle.Metadata.LicenseValid {
		t.Fatalf("expected license to be valid")
	}
}

func TestLoadBundle_BuildInfoMatch(t *testing.T) {
	buildInfo := []byte(`{"external_url":"https://example.com","version":"1.0.0","dashboard_url":"https://dash","deployment_id":"dep-1234"}`)
	trace := base64.StdEncoding.EncodeToString(buildInfo)
	tailnet := []byte(`<!-- trace ` + trace + ` -->`)
	reader, size := buildTestZip(t, map[string][]byte{
		"deployment/buildinfo.json":  buildInfo,
		"network/tailnet_debug.html": tailnet,
	})

	result := loadBundleFromZip(reader, size, "bundle.zip")
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	meta := result.Bundle.Metadata
	if !meta.BuildInfoMatch {
		t.Fatalf("expected build info to match tailnet trace")
	}
	if meta.BuildInfoMismatch != "" {
		t.Fatalf("unexpected build info mismatch: %s", meta.BuildInfoMismatch)
	}
}

func TestLoadBundle_NoProfiles(t *testing.T) {
	reader, size := buildTestZip(t, map[string][]byte{
		"license-status.txt": []byte(`{"external_url":"https://example.com"}`),
	})

	result := loadBundleFromZip(reader, size, "bundle.zip")
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if len(result.Bundle.Profiles) != 0 {
		t.Fatalf("expected no profiles, got %d", len(result.Bundle.Profiles))
	}
	foundWarning := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "No pprof profiles") {
			foundWarning = true
			break
		}
	}
	if !foundWarning {
		t.Fatalf("expected warning about missing pprof data")
	}
}

func TestLoadBundle_WithProfiles(t *testing.T) {
	profileData := makeTestProfile(t)
	reader, size := buildTestZip(t, map[string][]byte{
		"pprof/cpu.pprof": profileData,
	})

	result := loadBundleFromZip(reader, size, "bundle.zip")
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if len(result.Bundle.Profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(result.Bundle.Profiles))
	}
	for _, w := range result.Warnings {
		if strings.Contains(w, "No pprof profiles") {
			t.Fatalf("did not expect missing pprof warning when profiles are present")
		}
	}
}

func TestLoadBundle_CapturedTimeFromCLI(t *testing.T) {
	timestamp := "2025-09-25 06:28:00.579"
	logs := timestamp + " [info] capture\n"
	reader, size := buildTestZip(t, map[string][]byte{
		"cli_logs.txt": []byte(logs),
	})

	result := loadBundleFromZip(reader, size, "bundle.zip")
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}

	want, err := time.ParseInLocation("2006-01-02 15:04:05.000", timestamp, time.UTC)
	if err != nil {
		t.Fatalf("parse timestamp: %v", err)
	}

	if !result.Bundle.Created.Equal(want) {
		t.Fatalf("expected bundle created %v, got %v", want, result.Bundle.Created)
	}
}
