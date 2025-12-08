// Package parser handles parsing of Coder support bundles.
package parser

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	chromahtml "github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/google/pprof/profile"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
	"github.com/rowansmithau/coder-support-bundle-helper/internal/util"
)

// Constants
const (
	MaxGzipLayers    = 5
	MaxAgentLogBytes = 2 << 20 // 2MB
	AgentLogPath     = "agent/logs.txt"
)

// MakeID creates a unique ID from the given parts.
func MakeID(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// DetectAndDecompressAll repeatedly decompresses gzip data.
func DetectAndDecompressAll(data []byte) ([]byte, int, error) {
	layers := 0
	for layers < MaxGzipLayers {
		if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
			break
		}
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			break
		}
		decompressed, err := io.ReadAll(gr)
		_ = gr.Close()
		if err != nil {
			return nil, layers, err
		}
		data = decompressed
		layers++
	}
	return data, layers, nil
}

// ParseProfile parses a pprof profile from raw bytes.
func ParseProfile(name string, data []byte) (*profile.Profile, error) {
	decompressed, _, err := DetectAndDecompressAll(data)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}

	p, err := profile.ParseData(decompressed)
	if err != nil {
		return nil, fmt.Errorf("profile parse failed: %w", err)
	}

	return p, nil
}

// SampleTypeStrings extracts sample type strings from a profile.
func SampleTypeStrings(p *profile.Profile) []string {
	out := make([]string, 0, len(p.SampleType))
	for _, st := range p.SampleType {
		out = append(out, st.Type+"/"+st.Unit)
	}
	return out
}

// ProfileDurationSec returns the duration of a profile in seconds.
func ProfileDurationSec(p *profile.Profile) float64 {
	if p.DurationNanos > 0 {
		return float64(p.DurationNanos) / 1e9
	}
	return 0
}

// ProfileGroupFromPath extracts the group name from a profile path.
func ProfileGroupFromPath(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return ""
	}
	if parts[0] == "pprof" && len(parts) >= 3 {
		return parts[1]
	}
	return ""
}

// LoadResult holds the result of loading a bundle.
type LoadResult = models.LoadResult

// LoadBundleFromZip loads a support bundle from a zip file.
func LoadBundleFromZip(r io.ReaderAt, size int64, filename string, onProfileParsed func()) *LoadResult {
	result := &LoadResult{
		Warnings: []string{},
	}

	zr, err := zip.NewReader(r, size)
	if err != nil {
		result.Error = fmt.Errorf("failed to open zip: %w", err)
		return result
	}

	now := time.Now().UTC()
	b := &models.Bundle{
		ID:       MakeID(filepath.Base(filename), fmt.Sprintf("%d", now.UnixNano())),
		Name:     filepath.Base(filename),
		Created:  now,
		Path:     filename,
		Warnings: []string{},
		Metadata: &models.BundleMetadata{},
	}

	if captured := ParseBundleMetadata(zr, b.Metadata, &result.Warnings); captured != nil {
		b.Created = *captured
	}

	if logFile, warns := LoadAgentLog(zr); logFile != nil || len(warns) > 0 {
		if logFile != nil {
			b.AgentLog = logFile
		}
		if len(warns) > 0 {
			result.Warnings = append(result.Warnings, warns...)
		}
	}

	var (
		profs     []*models.StoredProfile
		promSnaps []*models.PrometheusSnapshot
	)
	for _, f := range zr.File {
		lower := strings.ToLower(f.Name)
		if strings.HasSuffix(lower, "prometheus.txt") {
			content, err := util.ReadZipFile(f)
			if err != nil {
				result.Warnings = append(result.Warnings, fmt.Sprintf("failed to read %s: %v", f.Name, err))
				continue
			}

			source := "unknown"
			switch {
			case strings.HasPrefix(lower, "agent/"):
				source = "agent"
			case strings.HasPrefix(lower, "deployment/"):
				source = "deployment"
			}

			promSnaps = append(promSnaps, &models.PrometheusSnapshot{
				ID:        MakeID(b.ID, f.Name),
				Name:      filepath.Base(f.Name),
				Source:    source,
				Path:      f.Name,
				Size:      len(content),
				CreatedAt: b.Created,
				Content:   content,
			})
			continue
		}

		if !strings.HasPrefix(f.Name, "pprof/") {
			continue
		}
		if !(strings.HasSuffix(lower, ".pprof") ||
			strings.HasSuffix(lower, ".pprof.gz") ||
			strings.HasSuffix(lower, ".prof.gz") ||
			strings.HasSuffix(lower, ".pb.gz")) {
			continue
		}

		content, err := util.ReadZipFile(f)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("failed to read %s: %v", f.Name, err))
			continue
		}

		p, err := ParseProfile(f.Name, content)
		if err != nil {
			result.Warnings = append(result.Warnings, fmt.Sprintf("failed to parse %s: %v", f.Name, err))
			continue
		}

		meta := map[string]string{}
		if cmdlineFile := util.FindSibling(zr, "pprof/cmdline.txt"); cmdlineFile != nil {
			if bb, err := util.ReadZipFile(cmdlineFile); err == nil {
				meta["cmdline.txt"] = strings.TrimSpace(string(bb))
			}
		}

		sp := &models.StoredProfile{
			ID:            MakeID(b.ID, filepath.Base(f.Name)),
			Name:          filepath.Base(f.Name),
			Path:          f.Name,
			SampleTypes:   SampleTypeStrings(p),
			PeriodType:    util.ValueOr(p.PeriodType, func(v *profile.ValueType) string { return v.Type }),
			PeriodUnit:    util.ValueOr(p.PeriodType, func(v *profile.ValueType) string { return v.Unit }),
			Duration:      ProfileDurationSec(p),
			SampleCount:   len(p.Sample),
			FunctionCount: len(p.Function),
			Bytes:         content,
			Profile:       p,
			Meta:          meta,
			CreatedAt:     time.Now(),
			Group:         ProfileGroupFromPath(f.Name),
		}
		profs = append(profs, sp)
		if onProfileParsed != nil {
			onProfileParsed()
		}
	}

	if len(profs) == 0 {
		result.Warnings = append(result.Warnings, "No pprof profiles found under pprof/ in the zip")
		b.Profiles = []*models.StoredProfile{}
	} else {
		sort.Slice(profs, func(i, j int) bool { return profs[i].Name < profs[j].Name })
		b.Profiles = profs
	}
	b.Prometheus = promSnaps
	b.Warnings = result.Warnings
	result.Bundle = b

	return result
}

// LoadAgentLog loads the agent log from a zip file.
func LoadAgentLog(zr *zip.Reader) (*models.BundleLog, []string) {
	f := util.FindSibling(zr, AgentLogPath)
	if f == nil {
		return nil, nil
	}

	content, truncated, err := util.ReadZipFileLimited(f, MaxAgentLogBytes)
	if err != nil {
		return nil, []string{fmt.Sprintf("failed to read %s: %v", f.Name, err)}
	}

	htmlOut, err := RenderLogHTML(content)
	var warnings []string
	if err != nil {
		warnings = append(warnings, fmt.Sprintf("failed to syntax-highlight %s: %v", f.Name, err))
	}

	lines := bytes.Count(content, []byte("\n"))
	if len(content) > 0 && content[len(content)-1] != '\n' {
		lines++
	}

	return &models.BundleLog{
		Path:            f.Name,
		Size:            int64(len(content)),
		Lines:           lines,
		Truncated:       truncated,
		HighlightedHTML: htmlOut,
	}, warnings
}

// RenderLogHTML renders log content as syntax-highlighted HTML.
func RenderLogHTML(content []byte) (string, error) {
	lexer := lexers.Get("log")
	if lexer == nil {
		lexer = lexers.Fallback
	}

	style := styles.Get("monokai")
	if style == nil {
		style = styles.Fallback
	}

	formatter := chromahtml.New(
		chromahtml.WithClasses(true),
		chromahtml.WithLineNumbers(true),
		chromahtml.LineNumbersInTable(true),
	)

	iterator, err := lexer.Tokenise(nil, string(content))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := formatter.Format(&buf, style, iterator); err != nil {
		return "", err
	}

	return buf.String(), nil
}
