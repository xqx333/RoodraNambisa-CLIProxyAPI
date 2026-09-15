package chatgptweb

import "encoding/json"

// LibraryStorageRejection recognizes the website's explicit upload error codes.
// over_user_quota is ambiguous and still requires the authoritative storage check.
// Generic HTTP 429, throttled, and image generation quotas are deliberately absent.
func LibraryStorageRejection(body []byte) bool {
	var value any
	if len(body) > 4<<20 || json.Unmarshal(body, &value) != nil {
		return false
	}
	var inspect func(any, int) bool
	inspect = func(value any, depth int) bool {
		if depth > 4 {
			return false
		}
		switch v := value.(type) {
		case string:
			return v == "library_storage_limit_exceeded" || v == "over_user_quota"
		case map[string]any:
			for _, key := range []string{"code", "error_code", "error", "detail"} {
				if inspect(v[key], depth+1) {
					return true
				}
			}
		}
		return false
	}
	return inspect(value, 0)
}
