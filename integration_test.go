//go:build integration

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_Integration_FindsDuplicates(t *testing.T) {
	root := t.TempDir()

	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	if err := os.WriteFile(a, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(b, []byte("hello\n"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "-root", root, "-workers", "2", "-quick-bytes", "0")
	cmd.Dir = filepath.Dir(a) // any dir; we'll override below
	cmd.Dir = filepath.Clean(getRepoRoot(t))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("go run failed: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "Duplicate group") {
		t.Fatalf("expected duplicate output, got:\n%s\nstderr:\n%s", out, stderr.String())
	}
	if !strings.Contains(out, a) || !strings.Contains(out, b) {
		t.Fatalf("expected both paths in output, got:\n%s", out)
	}
}

func TestCLI_Integration_NoDuplicates(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), []byte("b\n"), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}

	cmd := exec.Command("go", "run", ".", "-root", root, "-workers", "1", "-quick-bytes", "0")
	cmd.Dir = filepath.Clean(getRepoRoot(t))

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("go run failed: %v\nstderr:\n%s", err, stderr.String())
	}

	out := stdout.String()
	if !strings.Contains(out, "No duplicates found.") {
		t.Fatalf("expected 'No duplicates found.' output, got:\n%s\nstderr:\n%s", out, stderr.String())
	}
}

func getRepoRoot(t *testing.T) string {
	t.Helper()

	// The tests in this repo live at the module root, so the working directory
	// for `go test` is already the repo root.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	return wd
}

