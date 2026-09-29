package secretstore

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func testStore(t *testing.T) (*Store, string, string) {
	t.Helper()
	base := t.TempDir()
	sourceRoot := filepath.Join(base, "source")
	runtimeRoot := filepath.Join(base, "runtime")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := New(Config{
		Root:        sourceRoot,
		RuntimeRoot: runtimeRoot,
		GatewayUID:  os.Geteuid(),
		GatewayGID:  os.Getegid(),
		RequireRoot: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store, sourceRoot, runtimeRoot
}

func writeSourceSecret(t *testing.T, root string, mode os.FileMode) string {
	t.Helper()
	dir := filepath.Join(root, "providers")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(dir, "openai-main")
	if err := os.WriteFile(filename, []byte("provider-secret-value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filename, mode); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestStageCopiesProviderSecretIntoGatewayOnlyRuntimeRoot(t *testing.T) {
	store, sourceRoot, runtimeRoot := testStore(t)
	source := writeSourceSecret(t, sourceRoot, 0o600)

	target, err := store.Stage("secret://providers/openai-main", "attempt-001")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(target, runtimeRoot+string(filepath.Separator)) {
		t.Fatalf("staged secret escaped runtime root: %s", target)
	}
	if target == source {
		t.Fatal("secret store must stage a copy rather than bind the source secret directly")
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "provider-secret-value" {
		t.Fatal("staged provider secret content mismatch")
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o400 {
		t.Fatalf("staged provider secret mode = %o, want 0400", info.Mode().Perm())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing stat ownership")
	}
	if int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
		t.Fatalf("unexpected staged secret owner %d:%d", stat.Uid, stat.Gid)
	}
}

func TestStageRejectsWorldReadableSource(t *testing.T) {
	store, sourceRoot, _ := testStore(t)
	writeSourceSecret(t, sourceRoot, 0o644)

	if _, err := store.Stage("secret://providers/openai-main", "attempt-001"); err == nil {
		t.Fatal("expected world-readable provider secret source to be rejected")
	}
}

func TestStageRejectsSymlinkSource(t *testing.T) {
	store, sourceRoot, _ := testStore(t)
	target := filepath.Join(sourceRoot, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(sourceRoot, "providers")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "openai-main")); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Stage("secret://providers/openai-main", "attempt-001"); err == nil {
		t.Fatal("expected symlink provider secret source to be rejected")
	}
}

func TestStageRejectsHandleTraversal(t *testing.T) {
	store, sourceRoot, _ := testStore(t)
	writeSourceSecret(t, sourceRoot, 0o600)

	for _, handle := range []string{
		"secret://../openai-main",
		"secret:///providers/openai-main",
		"file://providers/openai-main",
		"secret://providers//openai-main",
	} {
		if _, err := store.Stage(handle, "attempt-001"); err == nil {
			t.Fatalf("expected handle %q to be rejected", handle)
		}
	}
}

func TestStageRejectsRuntimeReuse(t *testing.T) {
	store, sourceRoot, _ := testStore(t)
	writeSourceSecret(t, sourceRoot, 0o600)

	if _, err := store.Stage("secret://providers/openai-main", "attempt-001"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Stage("secret://providers/openai-main", "attempt-001"); err == nil {
		t.Fatal("expected duplicate per-attempt runtime secret staging to be rejected")
	}
}

func TestCleanupRemovesOnlyDerivedAttemptRuntimeDirectory(t *testing.T) {
	store, sourceRoot, runtimeRoot := testStore(t)
	writeSourceSecret(t, sourceRoot, 0o600)
	target, err := store.Stage("secret://providers/openai-main", "attempt-001")
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Cleanup("attempt-001"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("staged provider secret still exists: %v", err)
	}
	if _, err := os.Lstat(runtimeRoot); err != nil {
		t.Fatalf("runtime root itself must remain: %v", err)
	}
}

func TestStageRejectsIntermediateDirectorySymlink(t *testing.T) {
	store, sourceRoot, _ := testStore(t)
	external := t.TempDir()
	if err := os.WriteFile(filepath.Join(external, "openai-main"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, filepath.Join(sourceRoot, "providers")); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Stage("secret://providers/openai-main", "attempt-001"); err == nil {
		t.Fatal("expected intermediate provider secret directory symlink to be rejected")
	}
}
