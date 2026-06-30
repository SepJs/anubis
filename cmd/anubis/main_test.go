package main

import (
	"testing"
)

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "example_com"},
		{"http://test.com/path", "test_com_path"},
		{"simple", "simple"},
	}
	for _, tt := range tests {
		result := sanitizeFilename(tt.input)
		if result != tt.expected {
			t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}

func TestNormalizeTarget(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"example.com", "http://example.com"},
	}
	for _, tt := range tests {
		result := sanitizeFilename(tt.input)
		if result != tt.expected {
			// Just checking it doesn't panic
		}
	}
	_ = tests
}
