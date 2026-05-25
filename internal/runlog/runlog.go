// Package runlog opens per-run terminal log capture files.
package runlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Open returns an opened log file and the path that was opened. Relative paths
// are resolved from the executable directory so field-test artifacts sit beside
// the binary even when a service manager starts it from another working
// directory. Every call creates a fresh timestamped file; existing logs are
// never appended to or overwritten.
func Open(component, configuredPath string) (*os.File, string, error) {
	baseDir, err := executableDir()
	if err != nil {
		return nil, "", err
	}
	return openAt(baseDir, component, configuredPath)
}

func openAt(baseDir, component, configuredPath string) (*os.File, string, error) {
	component = strings.TrimSpace(component)
	if component == "" {
		component = "goose"
	}
	baseDir = strings.TrimSpace(baseDir)
	if baseDir == "" {
		baseDir = "."
	}
	configuredPath = strings.TrimSpace(configuredPath)
	if configuredPath != "" {
		path := filepath.Clean(configuredPath)
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, "", fmt.Errorf("create log directory: %w", err)
		}
		prefix, ext := splitLogName(filepath.Base(path))
		return createUniqueLogFile(filepath.Dir(path), prefix, ext)
	}

	dir := filepath.Join(baseDir, "logs")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, "", fmt.Errorf("create logs directory: %w", err)
	}
	return createUniqueLogFile(dir, component, ".log")
}

func executableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve executable path: %w", err)
	}
	return filepath.Dir(exe), nil
}

func splitLogName(name string) (string, string) {
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == string(filepath.Separator) {
		return "goose", ".log"
	}
	ext := filepath.Ext(name)
	prefix := strings.TrimSuffix(name, ext)
	if strings.TrimSpace(prefix) == "" {
		prefix = "goose"
	}
	if ext == "" {
		ext = ".log"
	}
	return prefix, ext
}

func createUniqueLogFile(dir, prefix, ext string) (*os.File, string, error) {
	stamp := time.Now().Format("20060102-150405")
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("%s-%s%s", prefix, stamp, ext)
		if i > 0 {
			name = fmt.Sprintf("%s-%s-%02d%s", prefix, stamp, i+1, ext)
		}
		path := filepath.Join(dir, name)
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err == nil {
			return f, path, nil
		}
		if os.IsExist(err) {
			continue
		}
		return nil, "", fmt.Errorf("open log file %q: %w", path, err)
	}
	return nil, "", fmt.Errorf("could not create a unique log file under %s for %s", dir, prefix)
}
