package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zeebo/blake3"
)

func TestLessSum(t *testing.T) {
	t.Parallel()

	var a, b [32]byte
	a[0] = 1
	b[0] = 2
	if !lessSum(a, b) {
		t.Fatalf("expected a < b")
	}
	if lessSum(b, a) {
		t.Fatalf("expected b !< a")
	}
	if lessSum(a, a) {
		t.Fatalf("expected a !< a")
	}
}

func TestQuickDigestFile_DisabledMatchesFullHash(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "file.bin")
	content := bytes.Repeat([]byte("abcdef0123456789"), 128) // 2048 bytes
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	full, err := blake3File(p)
	if err != nil {
		t.Fatalf("blake3File: %v", err)
	}
	quick, err := quickDigestFile(p, int64(len(content)), 0) // disabled => full hash
	if err != nil {
		t.Fatalf("quickDigestFile: %v", err)
	}
	if full != quick {
		t.Fatalf("expected quick (disabled) to match full hash")
	}
}

func TestQuickDigestFile_SamplesMatchExpected(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	p := filepath.Join(dir, "sampled.bin")

	// Make a deterministic file where start/middle/end samples are easy to reconstruct.
	content := bytes.Repeat([]byte("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"), 64) // 2304 bytes
	if err := os.WriteFile(p, content, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	size := int64(len(content))
	sampleBytes := int64(100)

	got, err := quickDigestFile(p, size, sampleBytes)
	if err != nil {
		t.Fatalf("quickDigestFile: %v", err)
	}

	// Expected: hash(start sample) + hash(middle sample) + hash(end sample).
	h := blake3.New()
	n := sampleBytes
	if n > size {
		n = size
	}

	start := content[0:n]
	midOff := (size / 2) - (n / 2)
	mid := content[midOff : midOff+n]
	end := content[size-n : size]

	_, _ = h.Write(start)
	_, _ = h.Write(mid)
	_, _ = h.Write(end)

	sum := h.Sum(nil)
	var want [32]byte
	copy(want[:], sum)

	if got != want {
		t.Fatalf("unexpected sample digest mismatch")
	}
}

func TestScanAndHashOnePass_FindsDuplicates(t *testing.T) {
	t.Parallel()

	root := t.TempDir()

	dupContent := []byte("same content\nsame content\n")
	a := filepath.Join(root, "a.txt")
	b := filepath.Join(root, "b.txt")
	c := filepath.Join(root, "c.txt")

	if err := os.WriteFile(a, dupContent, 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.WriteFile(b, dupContent, 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}
	if err := os.WriteFile(c, []byte("different\n"), 0o600); err != nil {
		t.Fatalf("write c: %v", err)
	}

	recs, quickErrs, fullErrs, walkErrs, fileCount, err := scanAndHashOnePass(root, 2, 0 /* quick disabled */)
	if err != nil {
		t.Fatalf("scanAndHashOnePass: %v", err)
	}
	if quickErrs != 0 || fullErrs != 0 || walkErrs != 0 {
		t.Fatalf("expected no errors, got quick=%d full=%d walk=%d", quickErrs, fullErrs, walkErrs)
	}
	if fileCount != 3 {
		t.Fatalf("expected fileCount=3, got %d", fileCount)
	}

	// Only duplicate candidates should be returned in recs.
	if len(recs) != 2 {
		t.Fatalf("expected 2 hashed recs, got %d", len(recs))
	}
	if recs[0].sum != recs[1].sum {
		t.Fatalf("expected duplicate hashes to match")
	}
	if recs[0].size != int64(len(dupContent)) || recs[1].size != int64(len(dupContent)) {
		t.Fatalf("expected duplicate sizes to match content length")
	}
}

func TestPrintDuplicateGroups_PrintsPaths(t *testing.T) {
	t.Parallel()

	// Capture stdout from printDuplicateGroups.
	origStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		_ = w.Close()
		os.Stdout = origStdout
	})

	var sum [32]byte
	sum[0] = 7
	recs := []hashedRec{
		{size: 10, sum: sum, path: "/tmp/a"},
		{size: 10, sum: sum, path: "/tmp/b"},
	}

	groups := printDuplicateGroups(recs)
	_ = w.Close()
	out, _ := io.ReadAll(r)

	if groups != 1 {
		t.Fatalf("expected 1 duplicate group, got %d", groups)
	}
	s := string(out)
	if !strings.Contains(s, "Duplicate group") {
		t.Fatalf("expected header in output, got: %q", s)
	}
	if !strings.Contains(s, "/tmp/a") || !strings.Contains(s, "/tmp/b") {
		t.Fatalf("expected paths in output, got: %q", s)
	}
}

