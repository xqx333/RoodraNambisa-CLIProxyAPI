package config

import (
	"fmt"
	"strings"
)

// NormalizeManagementAccessPath validates and normalizes the optional management access path.
func NormalizeManagementAccessPath(raw string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(raw), "/")
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) > 128 {
		return "", fmt.Errorf("must be at most 128 characters")
	}
	if trimmed == "." || trimmed == ".." {
		return "", fmt.Errorf("must not be %q", trimmed)
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.':
		default:
			return "", fmt.Errorf("contains unsupported character %q; use letters, digits, '-', '_' or '.'", r)
		}
	}
	return trimmed, nil
}

// ManagementAccessPathPrefix returns the URL prefix for the management access path.
func ManagementAccessPathPrefix(raw string) string {
	normalized, err := NormalizeManagementAccessPath(raw)
	if err != nil || normalized == "" {
		return ""
	}
	return "/" + normalized
}

// JoinManagementAccessPath prefixes a management route with the optional access path.
func JoinManagementAccessPath(accessPath, routePath string) string {
	prefix := ManagementAccessPathPrefix(accessPath)
	if !strings.HasPrefix(routePath, "/") {
		routePath = "/" + routePath
	}
	return prefix + routePath
}
