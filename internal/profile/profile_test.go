package profile

import (
	"testing"

	"github.com/rowansmithau/coder-support-bundle-helper/internal/models"
	"github.com/google/pprof/profile"
)

func makeTestProfile() *profile.Profile {
	return &profile.Profile{
		SampleType: []*profile.ValueType{
			{Type: "cpu", Unit: "nanoseconds"},
		},
		Sample: []*profile.Sample{
			{
				Location: []*profile.Location{
					{
						Line: []profile.Line{
							{Function: &profile.Function{ID: 1, Name: "main.foo", Filename: "main.go"}},
						},
					},
					{
						Line: []profile.Line{
							{Function: &profile.Function{ID: 2, Name: "main.bar", Filename: "main.go"}},
						},
					},
				},
				Value: []int64{100},
			},
			{
				Location: []*profile.Location{
					{
						Line: []profile.Line{
							{Function: &profile.Function{ID: 1, Name: "main.foo", Filename: "main.go"}},
						},
					},
				},
				Value: []int64{50},
			},
		},
		Function: []*profile.Function{
			{ID: 1, Name: "main.foo", Filename: "main.go"},
			{ID: 2, Name: "main.bar", Filename: "main.go"},
		},
	}
}

func TestBuildTop(t *testing.T) {
	p := makeTestProfile()

	rows, err := BuildTop(p, 0, "")
	if err != nil {
		t.Fatalf("BuildTop() error = %v", err)
	}

	if len(rows) == 0 {
		t.Fatal("BuildTop() returned no rows")
	}

	// Check that main.foo is in results (it's the leaf in both samples)
	var foundFoo bool
	for _, row := range rows {
		if row.Func == "main.foo" {
			foundFoo = true
			if row.Flat != 150 { // 100 + 50
				t.Errorf("main.foo Flat = %d, want 150", row.Flat)
			}
		}
	}
	if !foundFoo {
		t.Error("BuildTop() should include main.foo")
	}
}

func TestBuildTop_WithFilter(t *testing.T) {
	p := makeTestProfile()

	rows, err := BuildTop(p, 0, "bar")
	if err != nil {
		t.Fatalf("BuildTop() error = %v", err)
	}

	for _, row := range rows {
		if row.Func == "main.foo" && row.Flat > 0 {
			t.Error("Filter should exclude non-matching functions from flat")
		}
	}
}

func TestBuildFlame(t *testing.T) {
	p := makeTestProfile()

	root, err := BuildFlame(p, 0)
	if err != nil {
		t.Fatalf("BuildFlame() error = %v", err)
	}

	if root == nil {
		t.Fatal("BuildFlame() returned nil")
	}
	if root.Name != "root" {
		t.Errorf("root.Name = %q, want 'root'", root.Name)
	}
	if len(root.Children) == 0 {
		t.Error("BuildFlame() root should have children")
	}
}

func TestBuildFlameDiff(t *testing.T) {
	p1 := makeTestProfile()
	p2 := makeTestProfile()
	// Modify p2 to have different values
	p2.Sample[0].Value[0] = 200

	root, err := BuildFlameDiff(p1, p2, 0)
	if err != nil {
		t.Fatalf("BuildFlameDiff() error = %v", err)
	}

	if root == nil {
		t.Fatal("BuildFlameDiff() returned nil")
	}
	if root.Name != "root" {
		t.Errorf("root.Name = %q, want 'root'", root.Name)
	}
}

func TestCompareProfiles(t *testing.T) {
	p1 := &models.StoredProfile{
		Name:    "profile1",
		Profile: makeTestProfile(),
	}
	p2 := &models.StoredProfile{
		Name:    "profile2",
		Profile: makeTestProfile(),
	}
	p2.Profile.Sample[0].Value[0] = 200

	result, err := CompareProfiles(p1, p2, 0)
	if err != nil {
		t.Fatalf("CompareProfiles() error = %v", err)
	}

	if result.Profile1 != "profile1" || result.Profile2 != "profile2" {
		t.Error("CompareProfiles() should set profile names")
	}
	if len(result.Diff) == 0 {
		t.Error("CompareProfiles() should return diff rows")
	}
}
