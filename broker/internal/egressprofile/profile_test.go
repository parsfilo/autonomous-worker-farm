package egressprofile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sharedExample(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../../examples/egress-profile.example.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBindingHashMatchesSharedCrossLanguageVector(t *testing.T) {
	data, err := os.ReadFile("../../../examples/egress-profile-hash.vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]json.RawMessage
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	profile, err := Decode(vector["profile"])
	if err != nil {
		t.Fatal(err)
	}
	var expected string
	if err := json.Unmarshal(vector["expected_hash"], &expected); err != nil {
		t.Fatal(err)
	}
	if got := BindingHash(profile); got != expected {
		t.Fatalf("egress profile binding mismatch: got %s want %s", got, expected)
	}
}

func TestFreeBindingHashMatchesSharedCrossLanguageVector(t *testing.T) {
	data, err := os.ReadFile("../../../examples/egress-profile.opencode-free-hash.vector.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]json.RawMessage
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	profile, err := Decode(vector["profile"])
	if err != nil {
		t.Fatal(err)
	}
	var expected string
	if err := json.Unmarshal(vector["expected_hash"], &expected); err != nil {
		t.Fatal(err)
	}
	if got := BindingHash(profile); got != expected {
		t.Fatalf("free egress profile binding mismatch: got %s want %s", got, expected)
	}
}

func TestStoreLoadsAndResolvesTrustedProfile(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "llm-default.json")
	if err := os.WriteFile(filename, sharedExample(t), 0o600); err != nil {
		t.Fatal(err)
	}

	store, err := NewStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load("llm-default")
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Profile.ProfileID != "llm-default" {
		t.Fatalf("unexpected profile id: %s", loaded.Profile.ProfileID)
	}
	if len(loaded.Hash) != 64 {
		t.Fatalf("unexpected profile hash: %s", loaded.Hash)
	}
	route, err := loaded.Resolve("openai-responses", "gpt-5.2")
	if err != nil {
		t.Fatal(err)
	}
	if route.Protocol != "openai-responses" {
		t.Fatalf("unexpected route protocol: %s", route.Protocol)
	}
}

func TestStoreRejectsSymlinkProfile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, sharedExample(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "llm-default.json")); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("llm-default"); err == nil {
		t.Fatal("expected symlink profile to be rejected")
	}
}

func TestStoreRejectsWritableProfile(t *testing.T) {
	root := t.TempDir()
	filename := filepath.Join(root, "llm-default.json")
	if err := os.WriteFile(filename, sharedExample(t), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, 0o666); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("llm-default"); err == nil {
		t.Fatal("expected group/world writable profile to be rejected")
	}
}

func TestStoreRejectsFilenameIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "other.json"), sharedExample(t), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewStore(root, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load("other"); err == nil || !strings.Contains(err.Error(), "does not match filename") {
		t.Fatalf("expected profile id mismatch, got %v", err)
	}
}

func TestDecodeRejectsUnknownFields(t *testing.T) {
	var value map[string]any
	if err := json.Unmarshal(sharedExample(t), &value); err != nil {
		t.Fatal(err)
	}
	value["unexpected"] = true
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field rejection, got %v", err)
	}
}

func TestResolveRejectsUnapprovedModel(t *testing.T) {
	profile, err := Decode(sharedExample(t))
	if err != nil {
		t.Fatal(err)
	}
	loaded := Loaded{Profile: profile, Hash: BindingHash(profile)}
	if _, err := loaded.Resolve("openai-responses", "gpt-unapproved"); err == nil {
		t.Fatal("expected unapproved model to be rejected")
	}
}

func TestDecodeRejectsDormantHTTPProxyPort(t *testing.T) {
	var value map[string]any
	if err := json.Unmarshal(sharedExample(t), &value); err != nil {
		t.Fatal(err)
	}
	network := value["internal_network"].(map[string]any)
	network["http_proxy_port"] = 8080
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "reserved for opencode-free-connect") {
		t.Fatalf("expected dormant HTTP proxy port rejection, got %v", err)
	}
}

func TestDecodeRejectsNonSecretHandleScheme(t *testing.T) {
	var value map[string]any
	if err := json.Unmarshal(sharedExample(t), &value); err != nil {
		t.Fatal(err)
	}
	routes := value["routes"].([]any)
	route := routes[0].(map[string]any)
	route["secret_handle"] = "vault:openai-main"
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "secret handle") {
		t.Fatalf("expected secret handle scheme rejection, got %v", err)
	}
}

func freeConnectProfileBytes(t *testing.T) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(sharedExample(t), &value); err != nil {
		t.Fatal(err)
	}
	network := value["internal_network"].(map[string]any)
	network["http_proxy_port"] = 8888
	value["routes"] = []any{
		map[string]any{
			"route_id":          "opencode-free",
			"provider_id":       "opencode",
			"protocol":          "opencode-free-connect",
			"upstream_base_url": "https://opencode.ai",
			"worker_base_path":  "/",
			"worker_auth": map[string]any{
				"kind":        "none",
				"header_name": "",
				"secret_file": nil,
			},
			"upstream_auth": map[string]any{
				"kind":        "none",
				"header_name": "",
			},
			"secret_handle":         nil,
			"models":                []any{"opencode/*"},
			"request_path_prefixes": []any{},
		},
	}
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestFreeConnectRouteValidAndNamespaceLimited(t *testing.T) {
	profile, err := Decode(freeConnectProfileBytes(t))
	if err != nil {
		t.Fatal(err)
	}
	loaded := Loaded{Profile: profile, Hash: BindingHash(profile)}
	if _, err := loaded.Resolve("opencode-free", "opencode/space-bunny-free"); err != nil {
		t.Fatal(err)
	}
	if _, err := loaded.Resolve("opencode-free", "anthropic/claude-sonnet-5"); err == nil {
		t.Fatal("expected non-opencode namespace model to be rejected")
	}
}

func TestFreeConnectRouteRejectsAlternateOrigin(t *testing.T) {
	var value map[string]any
	if err := json.Unmarshal(freeConnectProfileBytes(t), &value); err != nil {
		t.Fatal(err)
	}
	routes := value["routes"].([]any)
	route := routes[0].(map[string]any)
	route["upstream_base_url"] = "https://example.com"
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "anonymous, secretless, host-pinned") {
		t.Fatalf("expected alternate origin rejection, got %v", err)
	}
}

func TestFreeConnectRouteRejectsSecretMaterial(t *testing.T) {
	var value map[string]any
	if err := json.Unmarshal(freeConnectProfileBytes(t), &value); err != nil {
		t.Fatal(err)
	}
	routes := value["routes"].([]any)
	route := routes[0].(map[string]any)
	route["secret_handle"] = "secret://providers/should-not-exist"
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(data); err == nil || !strings.Contains(err.Error(), "anonymous, secretless") {
		t.Fatalf("expected free route secret rejection, got %v", err)
	}
}
