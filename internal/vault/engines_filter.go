package vault

// FilterByType returns only mounts matching the given engine type.
func FilterByType(mounts []MountInfo, engineType string) []MountInfo {
	result := make([]MountInfo, 0)
	for _, m := range mounts {
		if m.Type == engineType {
			result = append(result, m)
		}
	}
	return result
}

// FilterByPath returns only mounts whose path contains the given substring.
func FilterByPath(mounts []MountInfo, substr string) []MountInfo {
	result := make([]MountInfo, 0)
	for _, m := range mounts {
		if len(substr) == 0 || contains(m.Path, substr) {
			result = append(result, m)
		}
	}
	return result
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(substr) == 0 ||
		(len(s) > 0 && indexOfSubstr(s, substr) >= 0))
}

func indexOfSubstr(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
