package vault

import "testing"

var testMounts = []MountInfo{
	{Path: "secret/", Type: "kv", Description: "kv store", Accessor: "kv_1"},
	{Path: "pki/", Type: "pki", Description: "pki engine", Accessor: "pki_1"},
	{Path: "transit/", Type: "transit", Description: "transit engine", Accessor: "tr_1"},
	{Path: "kv-v2/", Type: "kv", Description: "kv v2", Accessor: "kv_2"},
}

func TestFilterByType_KV(t *testing.T) {
	result := FilterByType(testMounts, "kv")
	if len(result) != 2 {
		t.Fatalf("expected 2 kv mounts, got %d", len(result))
	}
}

func TestFilterByType_NoMatch(t *testing.T) {
	result := FilterByType(testMounts, "aws")
	if len(result) != 0 {
		t.Fatalf("expected 0 mounts, got %d", len(result))
	}
}

func TestFilterByPath_Match(t *testing.T) {
	result := FilterByPath(testMounts, "pki")
	if len(result) != 1 {
		t.Fatalf("expected 1 mount, got %d", len(result))
	}
	if result[0].Type != "pki" {
		t.Errorf("expected pki type, got %s", result[0].Type)
	}
}

func TestFilterByPath_EmptySubstr(t *testing.T) {
	result := FilterByPath(testMounts, "")
	if len(result) != len(testMounts) {
		t.Fatalf("expected all mounts, got %d", len(result))
	}
}

func TestFilterByPath_KVPrefix(t *testing.T) {
	result := FilterByPath(testMounts, "kv")
	if len(result) != 1 {
		t.Fatalf("expected 1 match for 'kv' prefix path, got %d", len(result))
	}
}
