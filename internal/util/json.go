package util

import (
	"encoding/json"
	"fmt"
)

// UnmarshalJSON is a generic helper that unmarshals JSON content into the target type.
// It provides consistent error handling and reduces boilerplate across the codebase.
func UnmarshalJSON[T any](content []byte, target *T) error {
	if err := json.Unmarshal(content, target); err != nil {
		return fmt.Errorf("failed to unmarshal JSON: %w", err)
	}
	return nil
}

// UnmarshalJSONWithDefault unmarshals JSON content into the target type,
// returning defaultVal if unmarshaling fails.
func UnmarshalJSONWithDefault[T any](content []byte, defaultVal T) T {
	var result T
	if err := json.Unmarshal(content, &result); err != nil {
		return defaultVal
	}
	return result
}

// TryUnmarshalJSON attempts to unmarshal JSON content and returns success status.
// Useful when you want to try parsing without treating failure as an error.
func TryUnmarshalJSON[T any](content []byte, target *T) bool {
	return json.Unmarshal(content, target) == nil
}
