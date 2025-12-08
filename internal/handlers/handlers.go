// Package handlers provides HTTP handlers for the bundle viewer API.
package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/parser"
	profilepkg "github.com/rowansmithau/coder-support-bundle-helper/internal/profile"
)

// Store is the interface required by handlers.
type Store interface {
	GetAllBundles() []*models.Bundle
	GetBundle(id string) (*models.Bundle, bool)
	GetProfile(id string) (*models.StoredProfile, bool)
	SearchProfiles(query string) []*models.StoredProfile
	AddBundle(b *models.Bundle)
	GetTimeSeries(functionName string) []models.TimeSeriesPoint
}

// Config holds handler configuration.
type Config struct {
	MaxBundleSize   int64
	MaxAgentLogBytes int64
	OnProfileParsed func()
}

// WriteJSON writes v as JSON to w.
func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// ServeStatic creates handlers for static file serving.
func ServeStatic(contentType string, content []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", contentType)
		_, _ = w.Write(content)
	}
}

// ListBundles returns all bundles.
func ListBundles(s Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		bundles := s.GetAllBundles()
		WriteJSON(w, bundles)
	}
}

// GetBundle returns a single bundle by ID.
func GetBundle(s Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		b, ok := s.GetBundle(id)
		if !ok {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		WriteJSON(w, b)
	}
}

// BundleAgentLogs returns agent logs for a bundle.
func BundleAgentLogs(s Store, maxAgentLogBytes int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		b, ok := s.GetBundle(id)
		if !ok {
			http.Error(w, "bundle not found", http.StatusNotFound)
			return
		}
		if b.AgentLog == nil {
			http.Error(w, "agent logs not found", http.StatusNotFound)
			return
		}
		WriteJSON(w, map[string]any{
			"path":       b.AgentLog.Path,
			"size":       b.AgentLog.Size,
			"lines":      b.AgentLog.Lines,
			"truncated":  b.AgentLog.Truncated,
			"limitBytes": maxAgentLogBytes,
			"html":       b.AgentLog.HighlightedHTML,
		})
	}
}

// ProfileSummary returns profile metadata.
func ProfileSummary(s Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		p, ok := s.GetProfile(id)
		if !ok {
			http.Error(w, "profile not found", http.StatusNotFound)
			return
		}
		WriteJSON(w, p)
	}
}

// ProfileTop returns top functions from a profile.
func ProfileTop(s Store) http.HandlerFunc {
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

		rows, err := profilepkg.BuildTop(p.Profile, vi, filter)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		WriteJSON(w, rows)
	}
}

// ProfileFlame returns flame graph data for a profile.
func ProfileFlame(s Store) http.HandlerFunc {
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

		root, err := profilepkg.BuildFlame(p.Profile, vi)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		WriteJSON(w, root)
	}
}

// ProfileRaw returns raw profile data in various formats.
func ProfileRaw(s Store) http.HandlerFunc {
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
			w.Header().Set("Content-Type", "text/csv")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.csv", strconv.Quote(p.Name)))

			writer := csv.NewWriter(w)
			_ = writer.Write([]string{"Function", "File", "Flat", "Flat%", "Cum", "Cum%"})

			rows, _ := profilepkg.BuildTop(p.Profile, 0, "")
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
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", strconv.Quote(p.Name)))

			rows, _ := profilepkg.BuildTop(p.Profile, 0, "")
			WriteJSON(w, rows)

		default:
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", strconv.Quote(p.Name)))
			_, _ = w.Write(p.Bytes)
		}
	}
}

// CompareProfiles compares two profiles.
func CompareProfiles(s Store) http.HandlerFunc {
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

		result, err := profilepkg.CompareProfiles(p1, p2, vi)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		WriteJSON(w, result)
	}
}

// FlameDiff returns flame graph diff between two profiles.
func FlameDiff(s Store) http.HandlerFunc {
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

		result, err := profilepkg.BuildFlameDiff(p1.Profile, p2.Profile, vi)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		WriteJSON(w, result)
	}
}

// TimeSeries returns time series data for a function.
func TimeSeries(s Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		functionName := r.URL.Query().Get("function")
		points := s.GetTimeSeries(functionName)
		WriteJSON(w, points)
	}
}

// SearchProfiles searches profiles by query.
func SearchProfiles(s Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		profiles := s.SearchProfiles(query)
		WriteJSON(w, profiles)
	}
}

// UploadBundle handles bundle file uploads.
func UploadBundle(s Store, maxBundleSize int64, onProfileParsed func()) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		if header.Size > maxBundleSize {
			http.Error(w, fmt.Sprintf("bundle too large: %d bytes (max: %d)", header.Size, maxBundleSize), http.StatusRequestEntityTooLarge)
			return
		}

		tf, err := os.CreateTemp("", "upload-*.zip")
		if err != nil {
			http.Error(w, "failed to create temp file", http.StatusInternalServerError)
			return
		}
		defer tf.Close()
		defer os.Remove(tf.Name())

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

		if _, err := tf.Seek(0, 0); err != nil {
			http.Error(w, "failed to process upload", http.StatusInternalServerError)
			return
		}

		result := parser.LoadBundleFromZip(tf, fi.Size(), header.Filename, onProfileParsed)

		if result.Error != nil {
			http.Error(w, result.Error.Error(), http.StatusBadRequest)
			return
		}

		s.AddBundle(result.Bundle)

		response := map[string]interface{}{
			"bundle":   result.Bundle,
			"warnings": result.Warnings,
		}
		WriteJSON(w, response)
	}
}

// WithCORS wraps a handler with CORS headers.
func WithCORS(h http.Handler) http.Handler {
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
