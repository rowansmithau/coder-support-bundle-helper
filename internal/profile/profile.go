// Package profile provides pprof profile analysis functions.
package profile

import (
	"fmt"
	"regexp"
	"sort"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
	"github.com/google/pprof/profile"
)

// BuildTop builds a top-N view of the profile.
func BuildTop(p *profile.Profile, valueIndex int, filter string) ([]models.TopRow, error) {
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

	rows := []models.TopRow{}
	for fid, fv := range flat {
		mv := funcMeta[fid]
		cv := cum[fid]
		tr := models.TopRow{Func: mv.name, File: mv.file, Flat: fv, Cum: cv}
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
		tr := models.TopRow{Func: mv.name, File: mv.file, Flat: 0, Cum: cv}
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

// BuildFlame builds a flame graph from the profile.
func BuildFlame(p *profile.Profile, valueIndex int) (*models.FlameNode, error) {
	if valueIndex < 0 || valueIndex >= len(p.SampleType) {
		valueIndex = 0
	}

	root := &models.FlameNode{Name: "root"}

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
			cur = cur.GetChild(fn)
			cur.Value += v
		}
	}

	var sortRec func(n *models.FlameNode)
	sortRec = func(n *models.FlameNode) {
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

// BuildFlameDiff builds a flame graph diff between two profiles.
func BuildFlameDiff(p1, p2 *profile.Profile, valueIndex int) (*models.FlameDiffNode, error) {
	if valueIndex < 0 || valueIndex >= len(p1.SampleType) {
		valueIndex = 0
	}

	root := &models.FlameDiffNode{Name: "root"}

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
			cur = cur.GetChild(fn)
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
			cur = cur.GetChild(fn)
			cur.Value2 += v
		}
	}

	// Calculate diffs
	var calcDiffs func(n *models.FlameDiffNode)
	calcDiffs = func(n *models.FlameDiffNode) {
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
	var sortRec func(n *models.FlameDiffNode)
	sortRec = func(n *models.FlameDiffNode) {
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

// CompareProfiles compares two profiles and returns a diff.
func CompareProfiles(p1, p2 *models.StoredProfile, valueIndex int) (*models.ComparisonResult, error) {
	top1, err := BuildTop(p1.Profile, valueIndex, "")
	if err != nil {
		return nil, fmt.Errorf("build top for %s: %w", p1.Name, err)
	}

	top2, err := BuildTop(p2.Profile, valueIndex, "")
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
	result := &models.ComparisonResult{
		Profile1: p1.Name,
		Profile2: p2.Name,
		Diff:     []models.ComparisonDiffRow{},
	}

	for f := range allFuncs {
		v1 := flat1[f]
		v2 := flat2[f]
		diff := v2 - v1

		var pctDiff float64
		if v1 > 0 {
			pctDiff = float64(diff) * 100 / float64(v1)
		}

		result.Diff = append(result.Diff, models.ComparisonDiffRow{
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
