package util

import (
	"reflect"
	"testing"
)

func TestHumanizeKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"camelCase", "Camel Case"},
		{"snake_case", "Snake case"},  // underscores replaced with space, first letter capitalized
		{"already spaced", "Already spaced"},
		{"HTTPServer", "HTTPServer"},  // all caps preserved
		{"userID", "User ID"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := HumanizeKey(tt.input)
			if got != tt.want {
				t.Errorf("HumanizeKey(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDedupeStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"no duplicates", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b", "a", "c", "b"}, []string{"a", "b", "c"}},
		{"all same", []string{"x", "x", "x"}, []string{"x"}},
		{"empty", []string{}, []string{}},
		{"nil", nil, []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DedupeStrings(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DedupeStrings(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestValueOr(t *testing.T) {
	str := "hello"
	got := ValueOr(&str, func(s *string) string { return *s + " world" })
	if got != "hello world" {
		t.Errorf("ValueOr() = %q, want %q", got, "hello world")
	}

	got = ValueOr(nil, func(s *string) string { return *s })
	if got != "" {
		t.Errorf("ValueOr(nil) = %q, want empty", got)
	}
}

func TestCloneMap(t *testing.T) {
	original := map[string]string{"a": "1", "b": "2"}
	cloned := CloneMap(original)

	if !reflect.DeepEqual(cloned, original) {
		t.Errorf("CloneMap() = %v, want %v", cloned, original)
	}

	// Verify it's a copy
	cloned["c"] = "3"
	if _, ok := original["c"]; ok {
		t.Error("CloneMap() should create independent copy")
	}

	// Test nil
	if CloneMap(nil) != nil {
		t.Error("CloneMap(nil) should return nil")
	}
}
