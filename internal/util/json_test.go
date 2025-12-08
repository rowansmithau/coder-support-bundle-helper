package util

import (
	"testing"
)

func TestUnmarshalJSON(t *testing.T) {
	type Person struct {
		Name string `json:"name"`
		Age  int    `json:"age"`
	}

	// Valid JSON
	var p Person
	err := UnmarshalJSON([]byte(`{"name":"Alice","age":30}`), &p)
	if err != nil {
		t.Errorf("UnmarshalJSON() unexpected error: %v", err)
	}
	if p.Name != "Alice" || p.Age != 30 {
		t.Errorf("UnmarshalJSON() = %v, want {Alice, 30}", p)
	}

	// Invalid JSON
	var p2 Person
	err = UnmarshalJSON([]byte(`{invalid}`), &p2)
	if err == nil {
		t.Error("UnmarshalJSON() expected error for invalid JSON")
	}
}

func TestUnmarshalJSONWithDefault(t *testing.T) {
	type Config struct {
		Value int `json:"value"`
	}

	defaultVal := Config{Value: 42}

	got := UnmarshalJSONWithDefault([]byte(`{invalid}`), defaultVal)
	if got != defaultVal {
		t.Errorf("UnmarshalJSONWithDefault() = %v, want default %v", got, defaultVal)
	}

	got = UnmarshalJSONWithDefault([]byte(`{"value":100}`), defaultVal)
	if got.Value != 100 {
		t.Errorf("UnmarshalJSONWithDefault() = %v, want Value=100", got)
	}
}

func TestTryUnmarshalJSON(t *testing.T) {
	type Data struct {
		ID int `json:"id"`
	}

	var d Data
	ok := TryUnmarshalJSON([]byte(`{"id":123}`), &d)
	if !ok || d.ID != 123 {
		t.Errorf("TryUnmarshalJSON() = %v, %v; want {123}, true", d, ok)
	}

	var d2 Data
	ok = TryUnmarshalJSON([]byte(`invalid`), &d2)
	if ok {
		t.Errorf("TryUnmarshalJSON() should return false for invalid JSON")
	}
}
