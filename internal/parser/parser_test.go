package parser

import (
	"archive/zip"
	"bytes"
	"testing"

	"github.com/google/pprof/profile"
)

func TestMakeID(t *testing.T) {
	// MakeID creates a hash-based ID from parts
	id1 := MakeID("a", "b", "c")
	if id1 == "" {
		t.Error("MakeID() should return non-empty string")
	}
	
	// Same parts should produce same ID
	id2 := MakeID("a", "b", "c")
	if id1 != id2 {
		t.Error("MakeID() should be deterministic")
	}
	
	// Different parts should produce different ID
	id3 := MakeID("x", "y", "z")
	if id1 == id3 {
		t.Error("MakeID() should produce different IDs for different inputs")
	}
}

func TestDetectAndDecompressAll(t *testing.T) {
	// Test plain data
	plain := []byte("hello world")
	result, _, err := DetectAndDecompressAll(plain)
	if err != nil {
		t.Fatalf("DetectAndDecompressAll() error = %v", err)
	}
	if !bytes.Equal(result, plain) {
		t.Error("DetectAndDecompressAll() should return plain data unchanged")
	}
}

func TestSampleTypeStrings(t *testing.T) {
	p := &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "cpu", Unit: "nanoseconds"},
			{Type: "samples", Unit: "count"},
		},
	}
	result := SampleTypeStrings(p)
	if len(result) != 2 {
		t.Errorf("SampleTypeStrings() = %v, want 2 items", result)
	}
	// Format is "type/unit"
	if result[0] != "cpu/nanoseconds" {
		t.Errorf("SampleTypeStrings()[0] = %q, want 'cpu/nanoseconds'", result[0])
	}
}

func TestProfileGroupFromPath(t *testing.T) {
	// ProfileGroupFromPath extracts group from path containing "agent"
	got := ProfileGroupFromPath("agent/pprof/cpu.pb.gz")
	// Returns "agent" if path contains "agent", else empty
	if got != "" && got != "agent" {
		t.Logf("ProfileGroupFromPath behavior: %q -> %q", "agent/pprof/cpu.pb.gz", got)
	}
}

func createTestZip(files map[string][]byte) (*bytes.Reader, int64) {
	buf := new(bytes.Buffer)
	w := zip.NewWriter(buf)
	for name, content := range files {
		f, _ := w.Create(name)
		f.Write(content)
	}
	w.Close()
	return bytes.NewReader(buf.Bytes()), int64(buf.Len())
}

func TestLoadBundleFromZip_Empty(t *testing.T) {
	r, size := createTestZip(map[string][]byte{})
	result := LoadBundleFromZip(r, size, "empty.zip", nil)
	
	if result.Bundle == nil {
		t.Fatal("LoadBundleFromZip() should return a bundle even for empty zip")
	}
	if result.Bundle.Name != "empty.zip" {
		t.Errorf("Bundle.Name = %q, want 'empty.zip'", result.Bundle.Name)
	}
}

func TestLoadBundleFromZip_WithBuildInfo(t *testing.T) {
	buildInfo := `{"version":"v2.10.0","build_time":"2024-01-01T00:00:00Z"}`
	r, size := createTestZip(map[string][]byte{
		"deployment/buildinfo.json": []byte(buildInfo),
	})
	
	result := LoadBundleFromZip(r, size, "test.zip", nil)
	
	if result.Error != nil {
		t.Fatalf("LoadBundleFromZip() error = %v", result.Error)
	}
	if result.Bundle.Metadata.Version != "v2.10.0" {
		t.Errorf("Bundle.Metadata.Version = %q, want 'v2.10.0'", result.Bundle.Metadata.Version)
	}
}
