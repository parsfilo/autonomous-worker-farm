package secretstore

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
)

const maxSecretBytes = 16 * 1024

var identityPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

type Config struct {
	Root        string
	RuntimeRoot string
	GatewayUID  int
	GatewayGID  int
	RequireRoot bool
}

type Store struct {
	cfg Config
}

func New(cfg Config) (*Store, error) {
	if cfg.Root == "" || !filepath.IsAbs(cfg.Root) {
		return nil, errors.New("secret store root must be absolute")
	}
	if cfg.RuntimeRoot == "" || !filepath.IsAbs(cfg.RuntimeRoot) {
		return nil, errors.New("secret runtime root must be absolute")
	}
	cfg.Root = filepath.Clean(cfg.Root)
	cfg.RuntimeRoot = filepath.Clean(cfg.RuntimeRoot)
	if cfg.Root == cfg.RuntimeRoot || under(cfg.Root, cfg.RuntimeRoot) || under(cfg.RuntimeRoot, cfg.Root) {
		return nil, errors.New("secret source root and runtime root must be disjoint")
	}
	if cfg.GatewayUID <= 0 || cfg.GatewayGID <= 0 {
		return nil, errors.New("gateway UID/GID must be explicit non-root identities")
	}
	if cfg.RequireRoot && os.Geteuid() != 0 {
		return nil, errors.New("production secret store requires root")
	}
	return &Store{cfg: cfg}, nil
}

func (s *Store) Stage(secretHandle, attemptID string) (string, error) {
	if !identityPattern.MatchString(attemptID) {
		return "", errors.New("invalid attempt id for provider secret staging")
	}
	source, err := s.resolveHandle(secretHandle)
	if err != nil {
		return "", err
	}
	if err := verifySecretSource(source, s.cfg.RequireRoot); err != nil {
		return "", err
	}
	if err := s.ensureRuntimeRoot(); err != nil {
		return "", err
	}

	attemptDir := filepath.Join(s.cfg.RuntimeRoot, attemptID)
	if !under(s.cfg.RuntimeRoot, attemptDir) {
		return "", errors.New("provider secret runtime path escaped root")
	}
	if err := os.Mkdir(attemptDir, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return "", errors.New("provider secret runtime directory already exists")
		}
		return "", fmt.Errorf("create provider secret runtime directory: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			_ = os.RemoveAll(attemptDir)
		}
	}()

	data, err := os.ReadFile(source)
	if err != nil {
		return "", fmt.Errorf("read provider secret source: %w", err)
	}
	if len(data) == 0 || len(data) > maxSecretBytes || bytes.IndexByte(data, 0) >= 0 {
		return "", errors.New("provider secret source content is invalid")
	}

	target := filepath.Join(attemptDir, "provider-secret")
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create staged provider secret: %w", err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("write staged provider secret: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", fmt.Errorf("sync staged provider secret: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close staged provider secret: %w", err)
	}
	if err := os.Chown(target, s.cfg.GatewayUID, s.cfg.GatewayGID); err != nil {
		return "", fmt.Errorf("chown staged provider secret: %w", err)
	}
	if err := os.Chmod(target, 0o400); err != nil {
		return "", fmt.Errorf("chmod staged provider secret: %w", err)
	}

	rollback = false
	return target, nil
}

func (s *Store) Cleanup(attemptID string) error {
	if !identityPattern.MatchString(attemptID) {
		return errors.New("invalid attempt id for provider secret cleanup")
	}
	target := filepath.Join(s.cfg.RuntimeRoot, attemptID)
	if !under(s.cfg.RuntimeRoot, target) || target == s.cfg.RuntimeRoot {
		return errors.New("provider secret cleanup path escaped runtime root")
	}
	if err := os.RemoveAll(target); err != nil {
		return fmt.Errorf("remove provider secret runtime directory: %w", err)
	}
	return nil
}

func (s *Store) resolveHandle(secretHandle string) (string, error) {
	const prefix = "secret://"
	if !strings.HasPrefix(secretHandle, prefix) {
		return "", errors.New("provider secret handle must use secret://")
	}
	relative := strings.TrimPrefix(secretHandle, prefix)
	if relative == "" || strings.HasPrefix(relative, "/") || strings.Contains(relative, "\\") {
		return "", errors.New("invalid provider secret handle")
	}
	parts := strings.Split(relative, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." ||
			!regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$").MatchString(part) {
			return "", errors.New("invalid provider secret handle component")
		}
	}
	if err := s.verifySourceHierarchy(parts[:len(parts)-1]); err != nil {
		return "", err
	}
	target := filepath.Join(append([]string{s.cfg.Root}, parts...)...)
	if !under(s.cfg.Root, target) || target == s.cfg.Root {
		return "", errors.New("provider secret handle escaped source root")
	}
	return target, nil
}

func (s *Store) verifySourceHierarchy(parts []string) error {
	current := s.cfg.Root
	for index := -1; index < len(parts); index++ {
		if index >= 0 {
			current = filepath.Join(current, parts[index])
		}
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("stat provider secret directory: %w", err)
		}
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("provider secret hierarchy must contain only real directories")
		}
		if info.Mode().Perm()&0o022 != 0 {
			return errors.New("provider secret directory must not be group/world writable")
		}
		if s.cfg.RequireRoot {
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok || stat.Uid != 0 {
				return errors.New("production provider secret hierarchy must be root-owned")
			}
		}
	}
	resolved, err := filepath.EvalSymlinks(s.cfg.Root)
	if err != nil {
		return fmt.Errorf("resolve provider secret root: %w", err)
	}
	if filepath.Clean(resolved) != s.cfg.Root {
		return errors.New("provider secret root must not traverse symlinks")
	}
	return nil
}

func verifySecretSource(filename string, requireRoot bool) error {
	info, err := os.Lstat(filename)
	if err != nil {
		return fmt.Errorf("stat provider secret source: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("provider secret source must be a regular file")
	}
	if info.Size() <= 0 || info.Size() > maxSecretBytes {
		return errors.New("provider secret source size is invalid")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("provider secret source must not be group/world accessible")
	}
	if requireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("production provider secret source must be root-owned")
		}
	}
	return nil
}

func (s *Store) ensureRuntimeRoot() error {
	if err := os.MkdirAll(s.cfg.RuntimeRoot, 0o700); err != nil {
		return fmt.Errorf("create provider secret runtime root: %w", err)
	}
	info, err := os.Lstat(s.cfg.RuntimeRoot)
	if err != nil {
		return fmt.Errorf("stat provider secret runtime root: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("provider secret runtime root must be a real directory")
	}
	resolved, err := filepath.EvalSymlinks(s.cfg.RuntimeRoot)
	if err != nil {
		return fmt.Errorf("resolve provider secret runtime root: %w", err)
	}
	if filepath.Clean(resolved) != s.cfg.RuntimeRoot {
		return errors.New("provider secret runtime root must not traverse symlinks")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("provider secret runtime root must be owner-only")
	}
	if s.cfg.RequireRoot {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != 0 {
			return errors.New("production provider secret runtime root must be root-owned")
		}
	}
	return nil
}

func under(parent, child string) bool {
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	if child == parent {
		return true
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}
