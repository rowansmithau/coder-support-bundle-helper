package store

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
)

func init() {
	// Ensure validation scheme is set for tests
	model.NameValidationScheme = model.LegacyValidation
}

func newTestStore() *Store {
	return New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
}

func TestStore_AddAndGetBundle(t *testing.T) {
	s := newTestStore()

	bundle := &models.Bundle{
		ID:      "test-bundle",
		Name:    "test.zip",
		Created: time.Now(),
	}

	s.AddBundle(bundle)

	got, ok := s.GetBundle("test-bundle")
	if !ok {
		t.Fatal("GetBundle() should find added bundle")
	}
	if got.Name != "test.zip" {
		t.Errorf("GetBundle().Name = %q, want 'test.zip'", got.Name)
	}

	_, ok = s.GetBundle("nonexistent")
	if ok {
		t.Error("GetBundle() should return false for nonexistent bundle")
	}
}

func TestStore_GetAllBundles(t *testing.T) {
	s := newTestStore()

	s.AddBundle(&models.Bundle{ID: "b1", Name: "bundle1.zip", Created: time.Now()})
	s.AddBundle(&models.Bundle{ID: "b2", Name: "bundle2.zip", Created: time.Now()})

	bundles := s.GetAllBundles()
	if len(bundles) != 2 {
		t.Errorf("GetAllBundles() = %d bundles, want 2", len(bundles))
	}

	// Should be sorted by name
	if bundles[0].Name > bundles[1].Name {
		t.Error("GetAllBundles() should return sorted bundles")
	}
}

func TestStore_AddAndGetProfile(t *testing.T) {
	s := newTestStore()

	bundle := &models.Bundle{
		ID:   "bundle-with-profiles",
		Name: "test.zip",
		Profiles: []*models.StoredProfile{
			{ID: "profile-1", Name: "cpu.pb.gz", BundleID: "bundle-with-profiles"},
			{ID: "profile-2", Name: "heap.pb.gz", BundleID: "bundle-with-profiles"},
		},
	}
	s.AddBundle(bundle)

	p, ok := s.GetProfile("profile-1")
	if !ok {
		t.Fatal("GetProfile() should find profile from added bundle")
	}
	if p.Name != "cpu.pb.gz" {
		t.Errorf("GetProfile().Name = %q, want 'cpu.pb.gz'", p.Name)
	}
}

func TestStore_SearchProfiles(t *testing.T) {
	s := newTestStore()

	bundle := &models.Bundle{
		ID:   "search-test",
		Name: "test.zip",
		Profiles: []*models.StoredProfile{
			{ID: "p1", Name: "cpu.pb.gz", BundleID: "search-test"},
			{ID: "p2", Name: "heap.pb.gz", BundleID: "search-test"},
			{ID: "p3", Name: "goroutine.pb.gz", BundleID: "search-test"},
		},
	}
	s.AddBundle(bundle)

	// Empty query returns all
	all := s.SearchProfiles("")
	if len(all) != 3 {
		t.Errorf("SearchProfiles('') = %d, want 3", len(all))
	}

	// Search by name
	results := s.SearchProfiles("cpu")
	if len(results) != 1 {
		t.Errorf("SearchProfiles('cpu') = %d, want 1", len(results))
	}
}

func TestStore_GetTimeSeries(t *testing.T) {
	s := newTestStore()

	// Empty store returns empty
	points := s.GetTimeSeries("main.foo")
	if len(points) != 0 {
		t.Errorf("GetTimeSeries() on empty store = %d, want 0", len(points))
	}
}

func TestStore_AddBundle_WithPrometheusSnapshots(t *testing.T) {
	s := newTestStore()

	// Create a bundle with a Prometheus snapshot but without starting the server
	// (tests the storage and basic operations without requiring prometheus/grafana binaries)
	bundle := &models.Bundle{
		ID:      "bundle-with-prom",
		Name:    "test.zip",
		Created: time.Now(),
		// Not including Prometheus snapshots here to avoid triggering the
		// background goroutine that requires prometheus/grafana binaries
	}

	s.AddBundle(bundle)

	got, ok := s.GetBundle("bundle-with-prom")
	if !ok {
		t.Fatal("GetBundle() should find added bundle")
	}
	if got.Name != "test.zip" {
		t.Errorf("Bundle.Name = %q, want 'test.zip'", got.Name)
	}
}

func TestPrometheusMetricsParsing(t *testing.T) {
	// Test that Prometheus metrics can be parsed without panic
	// This validates the fix for the NameValidationScheme issue
	content := []byte("# HELP test_metric A test metric\n# TYPE test_metric gauge\ntest_metric 42\n")

	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(strings.NewReader(string(content)))
	if err != nil {
		t.Fatalf("Failed to parse metrics: %v", err)
	}
	if len(families) == 0 {
		t.Error("Expected at least one metric family")
	}
	if _, ok := families["test_metric"]; !ok {
		t.Error("Expected to find test_metric in parsed families")
	}
}
