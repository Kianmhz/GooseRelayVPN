package runlog

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestOpenCreatesDefaultTimestampedLogFile(t *testing.T) {
	dir := t.TempDir()

	f, path, err := openAt(dir, "goose-client", "")
	if err != nil {
		t.Fatalf("openAt: %v", err)
	}
	if _, err := f.WriteString("hello\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	slashPath := filepath.ToSlash(path)
	wantPrefix := filepath.ToSlash(filepath.Join(dir, "logs")) + "/goose-client-"
	if !strings.HasPrefix(slashPath, wantPrefix) || !strings.HasSuffix(slashPath, ".log") {
		t.Fatalf("path = %q, want %s*.log", path, wantPrefix)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(body) != "hello\n" {
		t.Fatalf("log body = %q, want hello", string(body))
	}
}

func TestOpenUsesCustomPathAsTimestampedPrefixAndCreatesParents(t *testing.T) {
	dir := t.TempDir()
	configured := filepath.Join("nested", "field-test.log")
	f, got, err := openAt(dir, "goose-server", configured)
	if err != nil {
		t.Fatalf("openAt: %v", err)
	}
	wantDir := filepath.Join(dir, "nested")
	if filepath.Dir(got) != wantDir {
		t.Fatalf("dir = %q, want %q", filepath.Dir(got), wantDir)
	}
	if matched, err := regexp.MatchString(`field-test-\d{8}-\d{6}(?:-\d{2})?\.log$`, filepath.Base(got)); err != nil || !matched {
		t.Fatalf("path = %q, want timestamped field-test log (match=%v err=%v)", got, matched, err)
	}
	if _, err := f.WriteString("server\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	body, err := os.ReadFile(got)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	if string(body) != "server\n" {
		t.Fatalf("log body = %q, want server", string(body))
	}
}

func TestOpenCustomPathCreatesFreshFileEachRun(t *testing.T) {
	dir := t.TempDir()
	configured := filepath.Join("logs", "server-field-test.log")

	first, firstPath, err := openAt(dir, "goose-server", configured)
	if err != nil {
		t.Fatalf("first openAt: %v", err)
	}
	if _, err := first.WriteString("first\n"); err != nil {
		t.Fatalf("write first: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close first: %v", err)
	}

	second, secondPath, err := openAt(dir, "goose-server", configured)
	if err != nil {
		t.Fatalf("second openAt: %v", err)
	}
	if _, err := second.WriteString("second\n"); err != nil {
		t.Fatalf("write second: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatalf("close second: %v", err)
	}

	if firstPath == secondPath {
		t.Fatalf("second run reused %q; want a fresh log file", firstPath)
	}
	firstBody, err := os.ReadFile(firstPath)
	if err != nil {
		t.Fatalf("read first: %v", err)
	}
	secondBody, err := os.ReadFile(secondPath)
	if err != nil {
		t.Fatalf("read second: %v", err)
	}
	if string(firstBody) != "first\n" {
		t.Fatalf("first log body = %q, want first only", string(firstBody))
	}
	if string(secondBody) != "second\n" {
		t.Fatalf("second log body = %q, want second only", string(secondBody))
	}
}
