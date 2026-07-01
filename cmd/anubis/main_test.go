package main

import (
	"testing"

	"github.com/SepJs/anubis/pkg/utils"
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
	// Verifies that utils.NormalizeTarget prepends http:// when no scheme is present.
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"example.com", "http://example.com"},
	}
	for _, tt := range tests {
		result := utils.NormalizeTarget(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", tt.input, result, tt.expected)
		}
	}
}
