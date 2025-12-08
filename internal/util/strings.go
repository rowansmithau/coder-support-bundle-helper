package util

import (
	"regexp"
	"strings"
)

var camelToWords = regexp.MustCompile(`([a-z])([A-Z])`)

// HumanizeKey converts camelCase or snake_case keys to human-readable form.
func HumanizeKey(key string) string {
	s := strings.ReplaceAll(key, "_", " ")
	s = camelToWords.ReplaceAllString(s, "$1 $2")
	if len(s) > 0 {
		s = strings.ToUpper(s[:1]) + s[1:]
	}
	return s
}

// DedupeStrings returns a slice with duplicate strings removed, preserving order.
func DedupeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	result := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; !ok {
			seen[item] = struct{}{}
			result = append(result, item)
		}
	}
	return result
}

// ValueOr returns a formatted string from a pointer using the provided function,
// or an empty string if the pointer is nil.
func ValueOr[T any](v *T, f func(*T) string) string {
	if v == nil {
		return ""
	}
	return f(v)
}

// CloneMap creates a shallow copy of a string map.
func CloneMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
