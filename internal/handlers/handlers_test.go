package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
)

// mockStore implements the Store interface for testing
type mockStore struct {
	bundles  map[string]*models.Bundle
	profiles map[string]*models.StoredProfile
}

func newMockStore() *mockStore {
	return &mockStore{
		bundles:  make(map[string]*models.Bundle),
		profiles: make(map[string]*models.StoredProfile),
	}
}

func (m *mockStore) GetAllBundles() []*models.Bundle {
	result := make([]*models.Bundle, 0, len(m.bundles))
	for _, b := range m.bundles {
		result = append(result, b)
	}
	return result
}

func (m *mockStore) GetBundle(id string) (*models.Bundle, bool) {
	b, ok := m.bundles[id]
	return b, ok
}

func (m *mockStore) GetProfile(id string) (*models.StoredProfile, bool) {
	p, ok := m.profiles[id]
	return p, ok
}

func (m *mockStore) SearchProfiles(query string) []*models.StoredProfile {
	return nil
}

func (m *mockStore) AddBundle(b *models.Bundle) {
	m.bundles[b.ID] = b
	for _, p := range b.Profiles {
		m.profiles[p.ID] = p
	}
}

func (m *mockStore) GetTimeSeries(functionName string) []models.TimeSeriesPoint {
	return nil
}

func TestListBundles(t *testing.T) {
	store := newMockStore()
	store.bundles["b1"] = &models.Bundle{ID: "b1", Name: "bundle1.zip"}
	store.bundles["b2"] = &models.Bundle{ID: "b2", Name: "bundle2.zip"}

	req := httptest.NewRequest(http.MethodGet, "/api/bundles", nil)
	rr := httptest.NewRecorder()

	ListBundles(store)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("ListBundles() status = %d, want %d", rr.Code, http.StatusOK)
	}

	var bundles []*models.Bundle
	if err := json.Unmarshal(rr.Body.Bytes(), &bundles); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}
	if len(bundles) != 2 {
		t.Errorf("ListBundles() returned %d bundles, want 2", len(bundles))
	}
}

func TestGetBundle(t *testing.T) {
	store := newMockStore()
	store.bundles["test-id"] = &models.Bundle{
		ID:      "test-id",
		Name:    "test.zip",
		Created: time.Now(),
	}

	// Found
	req := httptest.NewRequest(http.MethodGet, "/api/bundles/test-id", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "test-id"})
	rr := httptest.NewRecorder()

	GetBundle(store)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("GetBundle() status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Not found
	req = httptest.NewRequest(http.MethodGet, "/api/bundles/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	rr = httptest.NewRecorder()

	GetBundle(store)(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("GetBundle() for missing bundle status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestProfileSummary(t *testing.T) {
	store := newMockStore()
	store.profiles["p1"] = &models.StoredProfile{
		ID:   "p1",
		Name: "cpu.pb.gz",
	}

	req := httptest.NewRequest(http.MethodGet, "/api/profiles/p1/summary", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "p1"})
	rr := httptest.NewRecorder()

	ProfileSummary(store)(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("ProfileSummary() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestWithCORS(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := WithCORS(handler)

	// Regular request
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("WithCORS should set Access-Control-Allow-Origin header")
	}

	// OPTIONS request
	req = httptest.NewRequest(http.MethodOptions, "/", nil)
	rr = httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("WithCORS OPTIONS status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestWriteJSON(t *testing.T) {
	rr := httptest.NewRecorder()
	data := map[string]string{"key": "value"}

	WriteJSON(rr, data)

	if rr.Header().Get("Content-Type") != "application/json; charset=utf-8" {
		t.Error("WriteJSON should set Content-Type header")
	}

	var result map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("WriteJSON produced invalid JSON: %v", err)
	}
	if result["key"] != "value" {
		t.Error("WriteJSON should encode data correctly")
	}
}
